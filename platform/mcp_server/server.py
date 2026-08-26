"""MCP protocol server (JSON-RPC 2.0 over stdio).

Transport-agnostic core: :class:`McpServer.handle` maps one decoded JSON-RPC
message to at most one response dict (``None`` for notifications), so the
whole protocol is unit-testable without a subprocess. ``main()`` wires it
to newline-delimited stdio per the MCP spec.
"""

from __future__ import annotations

import json
import os
import sys
import time
from collections import deque

from .master_client import MasterClient
from .tools import FORBIDDEN_TOOL_NAMES, TOOL_DEFS, InvalidArguments, make_handlers

SUPPORTED_VERSIONS = ("2025-06-18", "2024-11-05")
LATEST_VERSION = SUPPORTED_VERSIONS[0]

# TUNABLE (manual-parameter pass pending): tool-call budget per MCP session.
# Env override: MCP_TOOL_CALLS_PER_MIN (<=0 disables limiting).
DEFAULT_TOOL_CALLS_PER_MIN = 120
_RATE_WINDOW_SECS = 60.0


def _env_tool_calls_per_min() -> int:
    raw = os.environ.get("MCP_TOOL_CALLS_PER_MIN", "").strip()
    if not raw:
        return DEFAULT_TOOL_CALLS_PER_MIN
    try:
        return int(raw)
    except ValueError:
        return DEFAULT_TOOL_CALLS_PER_MIN

SERVER_INFO = {"name": "bb-platform-mcp", "title": "Bug Bounty Platform MCP",
               "version": "0.1.0"}

INSTRUCTIONS = (
    "Gateway to an authorized-only bug bounty automation platform. "
    "Submit scans with list_workflows + submit_scan (scope is enforced "
    "server-side; out-of-scope targets are rejected). Only 'validated' "
    "findings are actionable — triage is performed by humans and cannot "
    "be done through this interface."
)

RESOURCES = [
    {"uri": "platform://workflows",
     "name": "Available workflows",
     "description": "Scan workflows this platform can run",
     "mimeType": "application/json"},
    {"uri": "platform://findings/actionable",
     "name": "Actionable findings",
     "description": ("Findings that are validated AND new — the only set an "
                     "agent should act on (Pillar B)"),
     "mimeType": "application/json"},
    {"uri": "platform://scans/recent",
     "name": "Recent scans",
     "description": "Latest scans with task-state rollups",
     "mimeType": "application/json"},
]


class McpServer:
    """JSON-RPC 2.0 dispatcher implementing the MCP server surface."""

    def __init__(self, client: MasterClient, tool_calls_per_min: int | None = None):
        self.client = client
        self.handlers = make_handlers(client)
        self.initialized = False
        self.protocol_version: str | None = None
        # Rate limiting (MCP spec: servers MUST rate-limit tool invocations).
        self.tool_calls_per_min = (_env_tool_calls_per_min()
                                   if tool_calls_per_min is None
                                   else int(tool_calls_per_min))
        self._call_times: deque[float] = deque()

    def _rate_limited(self) -> bool:
        """Sliding one-minute window; <=0 disables. Returns True when blocked."""
        if self.tool_calls_per_min <= 0:
            return False
        now = time.monotonic()
        while self._call_times and now - self._call_times[0] >= _RATE_WINDOW_SECS:
            self._call_times.popleft()
        if len(self._call_times) >= self.tool_calls_per_min:
            return True
        self._call_times.append(now)
        return False

    # ------------------------- plumbing ------------------------------- #
    @staticmethod
    def _result(msg_id, result: dict) -> dict:
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    @staticmethod
    def _error(msg_id, code: int, message: str, data=None) -> dict:
        err: dict = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        return {"jsonrpc": "2.0", "id": msg_id, "error": err}

    def handle_raw(self, line: str) -> dict | None:
        """One raw transport frame -> response dict or None."""
        try:
            msg = json.loads(line)
        except ValueError as exc:
            return self._error(None, -32700, f"parse error: {exc}")
        return self.handle(msg)

    # --------------------------- dispatch ----------------------------- #
    def handle(self, msg: dict) -> dict | None:
        if not isinstance(msg, dict) or not isinstance(msg.get("method"), str):
            return self._error(None, -32600, "invalid request")

        method = msg["method"]
        msg_id = msg.get("id")           # absent => notification semantics
        if "id" not in msg:
            return None                  # notifications are never answered
        params = msg.get("params") or {}
        if not isinstance(params, dict):
            params = {}

        try:
            if method == "initialize":
                return self._on_initialize(msg_id, params)
            if method == "ping":
                return self._result(msg_id, {})
            if method in ("tools/list", "tools/call",
                          "resources/list", "resources/read") \
                    and not self.initialized:
                return self._error(msg_id, -32002, "server not initialized")
            if method == "tools/list":
                return self._result(msg_id, {"tools": TOOL_DEFS})
            if method == "tools/call":
                return self._on_tools_call(msg_id, params)
            if method == "resources/list":
                return self._result(msg_id, {"resources": RESOURCES})
            if method == "resources/read":
                return self._on_resources_read(msg_id, params)
            return self._error(msg_id, -32601, f"method not found: {method}")
        except Exception as exc:         # noqa: BLE001 - never kill the loop
            return self._error(msg_id, -32603, f"internal error: {exc}")

    # ---------------------------- methods ------------------------------ #
    def _on_initialize(self, msg_id, params: dict) -> dict:
        requested = str(params.get("protocolVersion") or "")
        version = requested if requested in SUPPORTED_VERSIONS else LATEST_VERSION
        self.protocol_version = version
        self.initialized = True
        return self._result(msg_id, {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False},
                             "resources": {"listChanged": False}},
            "serverInfo": SERVER_INFO,
            "instructions": INSTRUCTIONS,
        })

    def _on_tools_call(self, msg_id, params: dict) -> dict:
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if name in FORBIDDEN_TOOL_NAMES:
            return self._error(msg_id, -32602,
                               f"tool {name!r} is human-only and is never "
                               "exposed to agents")
        handler = self.handlers.get(str(name))
        if handler is None:
            return self._error(msg_id, -32602, f"unknown tool: {name}")
        if not isinstance(arguments, dict):
            return self._error(msg_id, -32602, "arguments must be an object")
        if self._rate_limited():
            return self._error(
                msg_id, -32000, "rate limit exceeded",
                data={"limit_per_min": self.tool_calls_per_min})
        try:
            payload = handler(arguments)
        except InvalidArguments as exc:
            return self._error(msg_id, -32602, str(exc))
        except Exception as exc:         # noqa: BLE001 - business failure
            text = f"tool {name} failed: {exc}"
            return self._result(msg_id, {
                "content": [{"type": "text", "text": text}], "isError": True})
        body = json.dumps(payload, default=str)
        return self._result(msg_id, {
            "content": [{"type": "text", "text": body}],
            "structuredContent": payload,
            "isError": False,
        })

    def _on_resources_read(self, msg_id, params: dict) -> dict:
        uri = str(params.get("uri") or "")
        if uri == "platform://workflows":
            text = json.dumps({"workflows": self.client.list_workflows()})
        elif uri == "platform://findings/actionable":
            findings = self.client.list_findings(state="validated", is_new=True)
            text = json.dumps({"findings": findings}, default=str)
        elif uri == "platform://scans/recent":
            text = json.dumps({"scans": self.client.recent_scans()},
                              default=str)
        else:
            return self._error(msg_id, -32002, "resource not found",
                               data={"uri": uri})
        return self._result(msg_id, {"contents": [{
            "uri": uri, "mimeType": "application/json", "text": text,
        }]})


def main() -> None:  # pragma: no cover - stdio loop
    import os

    client = MasterClient(
        base_url=os.environ.get("MASTER_URL", "http://localhost:8080"),
        api_token=os.environ.get("MASTER_API_TOKEN", ""),
    )
    server = McpServer(client)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        response = server.handle_raw(line)
        if response is not None:
            sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()