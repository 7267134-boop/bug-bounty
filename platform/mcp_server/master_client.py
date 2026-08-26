"""Typed HTTP client for the Master REST API (stdlib only).

The MCP server is the ONLY component an AI agent reaches; this client is
the ONLY path from the MCP server to the platform. Every method maps to
one fixed endpoint with one fixed payload shape — no dynamic SQL, no
dynamic commands, nothing free-form.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request


class MasterClientError(RuntimeError):
    """Master answered with a non-2xx status (or the call failed)."""

    def __init__(self, status: int, detail: str):
        super().__init__(f"master returned {status}: {detail}")
        self.status = status
        self.detail = detail


def http_request(method: str, url: str, headers: dict,
                 body: bytes | None, timeout: float) -> tuple[int, bytes]:
    """Module-level so tests can stub the transport."""
    req = urllib.request.Request(url, data=body, method=method)
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


class MasterClient:
    def __init__(self, base_url: str = "http://localhost:8080",
                 api_token: str = "", timeout: float = 15.0):
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.timeout = timeout

    # ------------------------------------------------------------------ #
    def _request(self, method: str, path: str, body: dict | None = None,
                 raw_text: bool = False) -> dict | str:
        payload = json.dumps(body).encode() if body is not None else None
        headers = {"Accept": "application/json"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if self.api_token:
            headers["X-API-Token"] = self.api_token
        status, raw = http_request(method, f"{self.base_url}{path}",
                                   headers, payload, self.timeout)
        if raw_text:
            if status >= 400:
                raise MasterClientError(status, raw.decode(errors="replace")[:500])
            return raw.decode(errors="replace")
        try:
            doc = json.loads(raw.decode() or "{}")
        except ValueError:
            doc = {"raw": raw.decode(errors="replace")[:500]}
        if status >= 400:
            detail = doc.get("detail", doc) if isinstance(doc, dict) else doc
            raise MasterClientError(status, json.dumps(detail)[:500])
        return doc

    # --------------------------- typed ops ---------------------------- #
    def list_workflows(self) -> list[str]:
        return list(self._request("GET", "/api/v1/workflows").get("workflows", []))

    def submit_scan(self, program: str, workflow: str, targets: list[str],
                    requested_by: str) -> dict:
        return self._request("POST", "/api/v1/scans", {
            "program": program, "workflow": workflow,
            "targets": targets, "requested_by": requested_by,
        })

    def get_scan(self, scan_id: str) -> dict:
        return self._request("GET", f"/api/v1/scans/{scan_id}")

    def recent_scans(self, limit: int = 25) -> list[dict]:
        return list(self._request("GET", f"/api/v1/scans?limit={limit}")
                    .get("scans", []))

    def list_findings(self, scan_id: str | None = None, state: str | None = None,
                      severity: str | None = None, is_new: bool | None = None,
                      limit: int = 50) -> list[dict]:
        query: list[str] = [f"limit={limit}"]
        if scan_id:
            query.append(f"scan_id={scan_id}")
        if state:
            query.append(f"state={state}")
        if severity:
            query.append(f"severity={severity}")
        if is_new is not None:
            query.append(f"is_new={str(is_new).lower()}")
        import urllib.parse

        return list(self._request(
            "GET", "/api/v1/findings?" + "&".join(query)).get("findings", []))

    def metrics(self) -> dict:
        return self._request("GET", "/metrics")

    def get_scan_report(self, scan_id: str, fmt: str = "json") -> dict | str:
        """Stage 6 report: validated+new findings (server-side filtered)."""
        fmt = "md" if fmt == "md" else "json"
        return self._request(
            "GET", f"/api/v1/scans/{scan_id}/report?format={fmt}",
            raw_text=fmt == "md")
