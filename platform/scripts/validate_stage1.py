#!/usr/bin/env python3
"""Stage 1 end-to-end validation (run from a machine that can reach the API).

Checks, in order:
  1. /readyz reports postgres + redis healthy
  2. unauthenticated scan submission is rejected (401)
  3. out-of-scope target is rejected by the scope gate (403)
  4. hard-blocked endpoint (cloud metadata) is rejected (403)
  5. in-scope smoke scan is accepted (201), executes on the worker,
     and the scan reaches 'completed'

Usage:
    MASTER_URL=http://localhost:8080 MASTER_API_TOKEN=<token> \
        python scripts/validate_stage1.py
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ.get("MASTER_URL", "http://localhost:8080")
TOKEN = os.environ.get("MASTER_API_TOKEN", "")
TIMEOUT = int(os.environ.get("VALIDATION_TIMEOUT_SECS", "180"))

FAILURES: list[str] = []


def call(method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
    url = f"{BASE}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if TOKEN:
        req.add_header("X-API-Token", TOKEN)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode()
        try:
            payload = json.loads(payload or "{}")
        except ValueError:
            payload = {"raw": payload}
        # HTTPError detail nests under 'detail'
        if isinstance(payload, dict) and "detail" in payload:
            payload = payload["detail"] if isinstance(payload["detail"], dict) \
                else {"message": payload["detail"]}
        return exc.code, payload


def check(name: str, ok: bool, detail: str = "") -> None:
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {name}" + (f" - {detail}" if detail else ""))
    if not ok:
        FAILURES.append(name)


def main() -> int:
    status, body = call("GET", "/readyz")
    check("readiness", status == 200 and body.get("postgres") and body.get("redis"),
          json.dumps(body))

    status, body = call("POST", "/api/v1/scans", {
        "program": "demo", "workflow": "smoke",
        "targets": ["example.com"], "requested_by": "validator",
    })
    check("auth required (401 without token)", status == 401)

    status, body = call("POST", "/api/v1/scans", {
        "program": "demo", "workflow": "smoke",
        "targets": ["evil.not-in-scope.example.net"], "requested_by": "validator",
    })
    check("out-of-scope target blocked (403)", status == 403, json.dumps(body)[:120])

    status, body = call("POST", "/api/v1/scans", {
        "program": "demo", "workflow": "smoke",
        "targets": ["169.254.169.254"], "requested_by": "validator",
    })
    check("metadata endpoint blocked (403)", status == 403, json.dumps(body)[:120])

    status, body = call("POST", "/api/v1/scans", {
        "program": "demo", "workflow": "smoke",
        "targets": ["example.com", "admin.example.com"],
        "requested_by": "validator",
    })
    check("in-scope scan accepted (201)", status == 201, json.dumps(body)[:160])
    if status != 201:
        print("\nValidation aborted.")
        return 1

    decisions = {d["target"]: d["allowed"] for d in body.get("decisions", [])}
    check("deny entry excluded (admin.example.com)",
          decisions.get("admin.example.com") is False)
    scan_id = body["scan_id"]

    deadline = time.time() + TIMEOUT
    final_status = None
    while time.time() < deadline:
        _, snap = call("GET", f"/api/v1/scans/{scan_id}")
        final_status = snap.get("scan", {}).get("status")
        states = snap.get("task_states", {})
        if final_status in ("completed", "failed"):
            print(f"    scan reached terminal state: {final_status} {states}")
            break
        time.sleep(2)
    check("scan completed end-to-end", final_status == "completed")

    print()
    if FAILURES:
        print(f"RESULT: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("RESULT: all Stage 1 validation checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
