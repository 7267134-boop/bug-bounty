#!/usr/bin/env python3
"""Stage 5 acceptance: drive the MCP server over real stdio (no network).

Spawns ``python -m mcp_server.server`` as a subprocess, performs the MCP
handshake, lists tools, reads a resource, and verifies protocol invariants
(notifications are silent, unknown tools are rejected).

Usage (from platform/):  python scripts/mcp_smoke.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

FAILURES: list[str] = []


def send(proc: subprocess.Popen, msg: dict) -> None:
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()


def recv(proc: subprocess.Popen) -> dict:
    line = proc.stdout.readline()
    assert line.strip(), "server closed stdout unexpectedly"
    return json.loads(line)


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))
    if not ok:
        FAILURES.append(name)


def main() -> int:
    env = dict(os.environ, PYTHONPATH=os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))
    proc = subprocess.Popen(
        [sys.executable, "-m", "mcp_server.server"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        text=True, encoding="utf-8", env=env)

    try:
        # 1. handshake -----------------------------------------------------
        send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18",
                               "capabilities": {},
                               "clientInfo": {"name": "smoke", "version": "1"}}})
        resp = recv(proc)
        check("initialize", resp["result"]["protocolVersion"] == "2025-06-18"
              and resp["result"]["serverInfo"]["name"] == "bb-platform-mcp")

        # 2. initialized notification must be SILENT ------------------------
        send(proc, {"jsonrpc": "2.0",
                    "method": "notifications/initialized"})

        # 3. tools/list ------------------------------------------------------
        send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        resp = recv(proc)
        names = sorted(t["name"] for t in resp["result"]["tools"])
        check("tools/list returns typed tools",
              names == ["get_scan_report", "get_scan_status", "list_findings",
                        "list_workflows", "platform_metrics", "recent_scans",
                        "submit_scan"],
              ",".join(names))

        # 4. no triage tool / no shell tool ----------------------------------
        send(proc, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                    "params": {"name": "triage_finding",
                               "arguments": {"decision": "validated"}}})
        resp = recv(proc)
        check("triage refused as human-only",
              resp["error"]["code"] == -32602
              and "human-only" in resp["error"]["message"])

        # 5. resources/list ---------------------------------------------------
        send(proc, {"jsonrpc": "2.0", "id": 4, "method": "resources/list"})
        resp = recv(proc)
        uris = {r["uri"] for r in resp["result"]["resources"]}
        check("resources listed", "platform://findings/actionable" in uris)

        print()
        if FAILURES:
            print(f"RESULT: {len(FAILURES)} check(s) failed: {FAILURES}")
            return 1
        print("RESULT: all Stage 5 MCP smoke checks passed.")
        return 0
    finally:
        try:
            proc.stdin.close()
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())