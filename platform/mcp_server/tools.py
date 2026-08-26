"""Typed MCP tool surface.

Every tool is a fixed function with an explicit JSON schema; arguments are
validated locally BEFORE the Master is contacted (defense in depth — the
master validates again). There is deliberately NO tool for triage: the
validate/refute decision stays human-only (Pillar B), and NO tool that can
execute anything resembling a command.
"""

from __future__ import annotations

import re
from typing import Any, Callable

from .master_client import MasterClient

# Same charset the scope engine enforces on targets.
_TARGET_RE = re.compile(r"^[a-z0-9.:\-\*\[\]]{1,253}$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE)
SEVERITIES = ("critical", "high", "medium", "low", "info")
STATES = ("unvalidated", "validated", "refuted")


class InvalidArguments(ValueError):
    """Schema-level argument violation -> JSON-RPC -32602."""


def _clean_str(value: Any, name: str, max_len: int = 128) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidArguments(f"{name} must be a non-empty string")
    value = value.strip()
    if len(value) > max_len or any(c in value for c in "\r\n\x00"):
        raise InvalidArguments(f"{name} is too long or contains illegal characters")
    return value


def _check_targets(targets: Any) -> list[str]:
    if not isinstance(targets, list) or not 1 <= len(targets) <= 100:
        raise InvalidArguments("targets must be a list of 1..100 strings")
    cleaned = []
    for raw in targets:
        target = str(raw).strip().lower()
        if not _TARGET_RE.match(target):
            raise InvalidArguments(f"illegal target characters: {raw!r}")
        cleaned.append(target)
    return cleaned


def _opt_enum(value: Any, name: str, allowed: tuple[str, ...]) -> str | None:
    if value is None:
        return None
    value = str(value).strip().lower()
    if value not in allowed:
        raise InvalidArguments(f"{name} must be one of {sorted(allowed)}")
    return value


def _clamp_int(value: Any, name: str, default: int, low: int,
               high: int) -> int:
    if value is None:
        return default
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise InvalidArguments(f"{name} must be an integer") from None
    return max(low, min(high, number))


# --------------------------------------------------------------------- #
# Tool schemas (JSON Schema subset consumed by any MCP client)           #
# --------------------------------------------------------------------- #
TOOL_DEFS: list[dict] = [
    {
        "name": "list_workflows",
        "description": "List available scan workflows (smoke/recon/deep-recon/focused).",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "submit_scan",
        "description": ("Submit a scan for an authorized bug-bounty program. "
                        "Targets are re-validated against program scope by "
                        "the master; out-of-scope targets are rejected."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "program": {"type": "string", "description": "Program name"},
                "workflow": {"type": "string", "description": "Workflow name"},
                "targets": {"type": "array", "items": {"type": "string"},
                            "minItems": 1, "maxItems": 100},
                "requested_by": {"type": "string"},
            },
            "required": ["program", "workflow", "targets", "requested_by"],
        },
    },
    {
        "name": "get_scan_status",
        "description": "Get one scan's status plus its task-state breakdown.",
        "inputSchema": {
            "type": "object",
            "properties": {"scan_id": {"type": "string", "format": "uuid"}},
            "required": ["scan_id"],
        },
    },
    {
        "name": "list_findings",
        "description": ("Query findings. NOTE: only 'validated' findings are "
                        "actionable — 'unvalidated' items require human triage."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_id": {"type": "string", "format": "uuid"},
                "state": {"type": "string",
                          "enum": list(STATES)},
                "severity": {"type": "string", "enum": list(SEVERITIES)},
                "is_new": {"type": "boolean"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200},
            },
            "required": [],
        },
    },
    {
        "name": "recent_scans",
        "description": "Recent scans with task-state rollups.",
        "inputSchema": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "minimum": 1,
                                     "maximum": 100}},
            "required": [],
        },
    },
    {
        "name": "platform_metrics",
        "description": "Platform counters: scans/tasks by state, workers alive, findings.",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_scan_report",
        "description": ("Stage 6 report for one scan: ONLY human-validated AND "
                        "new findings (server-enforced), with CVSS scores and "
                        "safe PoC cURL commands. format: 'json' | 'md'."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_id": {"type": "string", "format": "uuid"},
                "format": {"type": "string", "enum": ["json", "md"]},
            },
            "required": ["scan_id"],
        },
    },
]

# Human-only operations are NOT exposed as tools. This is an invariant,
# guarded by tests: agents may READ triage state but never SET it.
FORBIDDEN_TOOL_NAMES = {"triage_finding", "validate_finding", "refute_finding"}


# --------------------------------------------------------------------- #
# Handlers                                                               #
# --------------------------------------------------------------------- #
def make_handlers(client: MasterClient) -> dict[str, Callable[[dict], dict]]:
    """Bind typed handlers to a master client."""

    def list_workflows(args: dict) -> dict:
        return {"workflows": client.list_workflows()}

    def submit_scan(args: dict) -> dict:
        program = _clean_str(args.get("program"), "program", 64)
        workflow = _clean_str(args.get("workflow"), "workflow", 64)
        requested_by = _clean_str(
            args.get("requested_by") or "mcp-agent", "requested_by")
        targets = _check_targets(args.get("targets"))
        return client.submit_scan(program, workflow, targets, requested_by)

    def get_scan_status(args: dict) -> dict:
        scan_id = _clean_str(args.get("scan_id"), "scan_id", 64)
        if not _UUID_RE.match(scan_id):
            raise InvalidArguments("scan_id must be a UUID")
        return client.get_scan(scan_id)

    def list_findings(args: dict) -> dict:
        scan_id = args.get("scan_id")
        if scan_id is not None:
            scan_id = _clean_str(scan_id, "scan_id", 64)
            if not _UUID_RE.match(scan_id):
                raise InvalidArguments("scan_id must be a UUID")
        return {"findings": client.list_findings(
            scan_id=scan_id,
            state=_opt_enum(args.get("state"), "state", STATES),
            severity=_opt_enum(args.get("severity"), "severity", SEVERITIES),
            is_new=bool(args["is_new"]) if "is_new" in args and
                    args["is_new"] is not None else None,
            limit=_clamp_int(args.get("limit"), "limit", 50, 1, 200),
        )}

    def recent_scans(args: dict) -> dict:
        return {"scans": client.recent_scans(
            limit=_clamp_int(args.get("limit"), "limit", 25, 1, 100))}

    def platform_metrics(args: dict) -> dict:
        return client.metrics()

    def get_scan_report(args: dict) -> dict | str:
        scan_id = _clean_str(args.get("scan_id"), "scan_id", 64)
        if not _UUID_RE.match(scan_id):
            raise InvalidArguments("scan_id must be a UUID")
        fmt = _opt_enum(args.get("format"), "format", ("json", "md")) or "json"
        report = client.get_scan_report(scan_id, fmt)
        if isinstance(report, str):
            return {"format": "md", "markdown": report}
        return report

    return {
        t["name"]: handler
        for t, handler in [
            (TOOL_DEFS[0], list_workflows),
            (TOOL_DEFS[1], submit_scan),
            (TOOL_DEFS[2], get_scan_status),
            (TOOL_DEFS[3], list_findings),
            (TOOL_DEFS[4], recent_scans),
            (TOOL_DEFS[5], platform_metrics),
            (TOOL_DEFS[6], get_scan_report),
        ]
    }
