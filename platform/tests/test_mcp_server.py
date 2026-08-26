"""Stage 5 tests: MCP server protocol + typed tool surface (offline).

The Master transport is stubbed at ``MasterClient._request`` with canned
routes; everything above it (protocol dispatch, validation, error mapping)
runs for real.
"""

import json

import pytest

from mcp_server.master_client import MasterClient, MasterClientError
from mcp_server.server import LATEST_VERSION, McpServer
from mcp_server.tools import FORBIDDEN_TOOL_NAMES, TOOL_DEFS


class FakeMaster(MasterClient):
    """Canned master: routes recorded, responses fixed."""

    def __init__(self):
        super().__init__("http://master.test", "tok")
        self.calls: list[tuple] = []

    def _request(self, method, path, body=None, raw_text=False):
        self.calls.append((method, path, body))
        routes = {
            ("GET", "/api/v1/workflows"):
                {"workflows": ["smoke", "recon", "deep-recon", "focused"]},
            ("POST", "/api/v1/scans"):
                {"scan_id": "11111111-1111-1111-1111-111111111111",
                 "tasks_enqueued": 2,
                 "decisions": [{"target": "example.com", "allowed": True}]},
            ("GET", "/metrics"):
                {"scans": {"running": 1}, "workers_alive": 2,
                 "findings_total": 42, "findings_new": 3},
        }
        if (method, path.split("?")[0]) == ("GET", "/api/v1/scans") \
                and method == "GET" and "?" not in path:
            return {"scans": [{"scan_id": "abc", "status": "completed"}]}
        if method == "POST" and path.endswith("/scans"):
            # simulate the master's scope gate: evil targets get rejected
            if any(str(t).startswith("evil") for t in (body or {}).get("targets", [])):
                raise MasterClientError(
                    403, json.dumps({"targets": [{"target": body["targets"][0],
                                                  "allowed": False}]}))
            return {"scan_id": "11111111-1111-1111-1111-111111111111",
                    "tasks_enqueued": 2,
                    "decisions": [{"target": "example.com", "allowed": True}]}
        if method == "GET" and "/report?" in path:
            scan_id = path.split("/api/v1/scans/")[1].split("/")[0]
            if scan_id == "22222222-2222-2222-2222-222222222222":
                raise MasterClientError(404, '"scan not found"')
            if "format=md" in path:
                return "# Bug Bounty Report — recon scan\n"
            return {"report_version": 1, "scan": {"scan_id": scan_id},
                    "findings": [{"rank": 1, "type": "vulnerability",
                                  "severity": "high"}]}
        if method == "GET" and path.startswith("/api/v1/scans/"):
            scan_id = path.rsplit("/", 1)[-1]
            if scan_id == "22222222-2222-2222-2222-222222222222":
                raise MasterClientError(404, '"scan not found"')
            return {"scan": {"scan_id": scan_id, "status": "running"},
                    "task_states": {"succeeded": 2}}
        if method == "GET" and path.startswith("/api/v1/findings"):
            return {"findings": [{"id": "f1", "type": "vulnerability"}]}
        routes = {
            ("GET", "/api/v1/workflows"):
                {"workflows": ["smoke", "recon", "deep-recon", "focused"]},
            ("GET", "/metrics"):
                {"scans": {"running": 1}, "workers_alive": 2,
                 "findings_total": 42, "findings_new": 3},
        }
        if (method, path) in routes:
            return routes[(method, path)]
        raise MasterClientError(500, "unrouted")


@pytest.fixture()
def server():
    return McpServer(FakeMaster())


def init(server, version="2025-06-18", msg_id=1):
    return server.handle({
        "jsonrpc": "2.0", "id": msg_id, "method": "initialize",
        "params": {"protocolVersion": version,
                   "capabilities": {},
                   "clientInfo": {"name": "test-agent", "version": "1.0"}},
    })


def call_tool(server, name, arguments, msg_id=10):
    return server.handle({
        "jsonrpc": "2.0", "id": msg_id, "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    })


# --------------------------------------------------------------------- #
# Lifecycle                                                              #
# --------------------------------------------------------------------- #
class TestLifecycle:
    def test_initialize_echoes_supported_version(self, server):
        resp = init(server)
        assert resp["result"]["protocolVersion"] == "2025-06-18"
        assert "tools" in resp["result"]["capabilities"]
        assert "resources" in resp["result"]["capabilities"]
        assert resp["result"]["serverInfo"]["name"] == "bb-platform-mcp"

    def test_initialize_negotiates_older_version(self, server):
        resp = init(server, version="2024-11-05")
        assert resp["result"]["protocolVersion"] == "2024-11-05"

    def test_initialize_unsupported_version_returns_latest(self, server):
        resp = init(server, version="0.9-beta")
        assert resp["result"]["protocolVersion"] == LATEST_VERSION

    def test_initialized_notification_is_silent(self, server):
        assert server.handle({"jsonrpc": "2.0",
                              "method": "notifications/initialized"}) is None

    def test_tools_blocked_before_initialize(self, server):
        resp = server.handle({"jsonrpc": "2.0", "id": 5,
                              "method": "tools/list"})
        assert resp["error"]["code"] == -32002

    def test_ping_works_anytime(self, server):
        resp = server.handle({"jsonrpc": "2.0", "id": 7, "method": "ping"})
        assert resp["result"] == {}

    def test_unknown_method_minus_32601(self, server):
        init(server)
        resp = server.handle({"jsonrpc": "2.0", "id": 8,
                              "method": "prompts/list"})
        assert resp["error"]["code"] == -32601

    def test_parse_error_frame(self, server):
        resp = server.handle_raw('{"jsonrpc": "2.0", oops')
        assert resp["error"]["code"] == -32700

    def test_invalid_request_frame(self, server):
        assert server.handle("not-a-dict")["error"]["code"] == -32600
        assert server.handle({"jsonrpc": "2.0", "id": 1})["error"]["code"] \
            == -32600


# --------------------------------------------------------------------- #
# Tool surface                                                           #
# --------------------------------------------------------------------- #
class TestToolSurface:
    def test_exactly_the_typed_tools(self, server):
        init(server)
        resp = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = {t["name"] for t in resp["result"]["tools"]}
        assert names == {"list_workflows", "submit_scan", "get_scan_status",
                         "list_findings", "recent_scans", "platform_metrics",
                         "get_scan_report"}
        for tool in resp["result"]["tools"]:
            assert tool["inputSchema"]["type"] == "object"
            assert isinstance(tool["inputSchema"].get("required", []), list)

    def test_no_triage_tool_is_ever_exposed(self):
        """Invariant: validate/refute stays human-only (Pillar B)."""
        names = {t["name"] for t in TOOL_DEFS}
        assert not (names & FORBIDDEN_TOOL_NAMES)

    def test_triage_call_rejected_even_if_asked_by_name(self, server):
        init(server)
        for forbidden in FORBIDDEN_TOOL_NAMES:
            resp = call_tool(server, forbidden, {})
            assert resp["error"]["code"] == -32602
            assert "human-only" in resp["error"]["message"]

    def test_unknown_tool_minus_32602(self, server):
        init(server)
        resp = call_tool(server, "run_shell", {"command": "rm -rf /"})
        assert resp["error"]["code"] == -32602


# --------------------------------------------------------------------- #
# Tool behaviour                                                         #
# --------------------------------------------------------------------- #
class TestToolCalls:
    def test_submit_scan_happy_path(self, server):
        init(server)
        resp = call_tool(server, "submit_scan", {
            "program": "demo", "workflow": "recon",
            "targets": ["EXAMPLE.com", "sub.example.com"],
            "requested_by": "ai-agent-01"})
        result = resp["result"]
        assert result["isError"] is False
        payload = json.loads(result["content"][0]["text"])
        assert payload["scan_id"] == "11111111-1111-1111-1111-111111111111"
        # typed request actually reached the master, normalized
        method, path, body = server.client.calls[-1]
        assert (method, path) == ("POST", "/api/v1/scans")
        assert body["targets"] == ["example.com", "sub.example.com"]
        assert body["program"] == "demo"

    def test_submit_scan_injection_target_blocked_locally(self, server):
        init(server)
        before = len(server.client.calls)
        resp = call_tool(server, "submit_scan", {
            "program": "demo", "workflow": "recon",
            "targets": ["example.com; rm -rf /"], "requested_by": "agent"})
        assert resp["error"]["code"] == -32602
        assert len(server.client.calls) == before      # master never called

    def test_submit_scan_out_of_scope_maps_to_is_error(self, server):
        init(server)
        resp = call_tool(server, "submit_scan", {
            "program": "demo", "workflow": "recon",
            "targets": ["evil-not-in-scope.com"], "requested_by": "agent"})
        # master's 403 is a *business* result, not a protocol error
        assert "error" not in resp
        assert resp["result"]["isError"] is True
        assert "403" in resp["result"]["content"][0]["text"]

    def test_get_scan_status_uuid_enforced(self, server):
        init(server)
        resp = call_tool(server, "get_scan_status", {"scan_id": "../../etc"})
        assert resp["error"]["code"] == -32602
        ok = call_tool(server, "get_scan_status",
                       {"scan_id": "33333333-3333-3333-3333-333333333333"})
        assert ok["result"]["structuredContent"]["scan"]["status"] == "running"

    def test_get_scan_missing_maps_to_is_error(self, server):
        init(server)
        resp = call_tool(server, "get_scan_status",
                         {"scan_id": "22222222-2222-2222-2222-222222222222"})
        assert resp["result"]["isError"] is True

    def test_list_findings_validates_and_clamps(self, server):
        init(server)
        bad = call_tool(server, "list_findings", {"severity": "apocalyptic"})
        assert bad["error"]["code"] == -32602

        resp = call_tool(server, "list_findings",
                         {"state": "validated", "is_new": True, "limit": 99999})
        findings = resp["result"]["structuredContent"]["findings"]
        assert findings[0]["id"] == "f1"
        method, path, _ = server.client.calls[-1]
        assert "limit=200" in path                      # clamped
        assert "state=validated" in path and "is_new=true" in path

    def test_metrics_roundtrip(self, server):
        init(server)
        resp = call_tool(server, "platform_metrics", {})
        data = resp["result"]["structuredContent"]
        assert data["workers_alive"] == 2 and data["findings_total"] == 42

    def test_report_json_and_md(self, server):
        init(server)
        scan_id = "44444444-4444-4444-4444-444444444444"
        resp = call_tool(server, "get_scan_report", {"scan_id": scan_id})
        data = resp["result"]["structuredContent"]
        assert data["report_version"] == 1
        assert data["findings"][0]["severity"] == "high"

        resp = call_tool(server, "get_scan_report",
                         {"scan_id": scan_id, "format": "md"})
        text = json.loads(resp["result"]["content"][0]["text"])
        assert "# Bug Bounty Report" in text["markdown"]

    def test_report_missing_scan_is_error_not_protocol_error(self, server):
        init(server)
        resp = call_tool(server, "get_scan_report",
                         {"scan_id": "22222222-2222-2222-2222-222222222222"})
        assert "error" not in resp and resp["result"]["isError"] is True

    def test_report_bad_format_rejected_locally(self, server):
        init(server)
        before = len(server.client.calls)
        resp = call_tool(server, "get_scan_report",
                         {"scan_id": "44444444-4444-4444-4444-444444444444",
                          "format": "html"})
        assert resp["error"]["code"] == -32602
        assert len(server.client.calls) == before


# --------------------------------------------------------------------- #
# Resources                                                              #
# --------------------------------------------------------------------- #
class TestResources:
    def test_list_resources(self, server):
        init(server)
        resp = server.handle({"jsonrpc": "2.0", "id": 20,
                              "method": "resources/list"})
        uris = {r["uri"] for r in resp["result"]["resources"]}
        assert uris == {"platform://workflows",
                        "platform://findings/actionable",
                        "platform://scans/recent"}

    def test_read_actionable_findings_forces_pillar_b_filters(self, server):
        """The resource MUST pin state=validated + is_new=true server-side."""
        init(server)
        resp = server.handle({"jsonrpc": "2.0", "id": 21,
                              "method": "resources/read",
                              "params": {"uri":
                                         "platform://findings/actionable"}})
        content = resp["result"]["contents"][0]
        assert content["mimeType"] == "application/json"
        assert json.loads(content["text"])["findings"][0]["id"] == "f1"
        _, path, _ = server.client.calls[-1]
        assert "state=validated" in path and "is_new=true" in path

    def test_unknown_resource_minus_32002(self, server):
        init(server)
        resp = server.handle({"jsonrpc": "2.0", "id": 22,
                              "method": "resources/read",
                              "params": {"uri": "file:///etc/passwd"}})
        assert resp["error"]["code"] == -32002


# --------------------------------------------------------------------- #
# Rate limiting (MCP spec: servers MUST rate-limit tool invocations)     #
# --------------------------------------------------------------------- #
class TestRateLimit:
    def test_calls_beyond_budget_rejected_with_data(self):
        server = McpServer(FakeMaster(), tool_calls_per_min=1)
        init(server)
        ok = call_tool(server, "list_workflows", {})
        assert ok["result"]["isError"] is False
        blocked = call_tool(server, "list_workflows", {})
        assert blocked["error"]["code"] == -32000
        assert blocked["error"]["message"] == "rate limit exceeded"
        assert blocked["error"]["data"]["limit_per_min"] == 1

    def test_zero_or_negative_disables_limiting(self):
        server = McpServer(FakeMaster(), tool_calls_per_min=0)
        init(server)
        for _ in range(5):
            resp = call_tool(server, "platform_metrics", {})
            assert "error" not in resp

    def test_resources_are_not_rate_limited(self):
        server = McpServer(FakeMaster(), tool_calls_per_min=1)
        init(server)
        # burn the single tool-call budget
        call_tool(server, "platform_metrics", {})
        resp = server.handle({"jsonrpc": "2.0", "id": 30,
                              "method": "resources/list"})
        assert "error" not in resp

    def test_env_override_parsed_and_invalid_falls_back(self, monkeypatch):
        from mcp_server.server import (_env_tool_calls_per_min,
                                       DEFAULT_TOOL_CALLS_PER_MIN)

        monkeypatch.setenv("MCP_TOOL_CALLS_PER_MIN", "7")
        assert _env_tool_calls_per_min() == 7
        monkeypatch.setenv("MCP_TOOL_CALLS_PER_MIN", "not-a-number")
        assert _env_tool_calls_per_min() == DEFAULT_TOOL_CALLS_PER_MIN
        monkeypatch.delenv("MCP_TOOL_CALLS_PER_MIN")
        assert _env_tool_calls_per_min() == DEFAULT_TOOL_CALLS_PER_MIN