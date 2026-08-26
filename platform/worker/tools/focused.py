"""Focused-scanning wrappers (Stage 4): XSS analysis & visual reconnaissance.

PoC pair for the tool-expansion phase:
  * dalfox     – context-aware XSS scanner, fed ``url_param`` findings
  * gowitness  – headless screenshots of live hosts

Both inherit the platform guarantees: argv-list only (no shell), input
materialized by the worker from the findings store, rate-limited launches,
and namespace-safe output parsing.
"""

from __future__ import annotations

import os

from .base import ExecResult, ToolContext, ToolWrapper
from .registry import register
from .recon_enum import _dedupe, _json_lines


@register
class DalfoxTool(ToolWrapper):
    """Context-aware XSS scanner over discovered parameterized URLs.

    consumes: url_param   (emitted by katana / waybackurls)
    produces: vulnerability (id='dalfox-xss', one per matched URL)
    """

    name = "dalfox"
    binary = "dalfox"
    description = "Parameter analysis & reflected/DOM XSS scanning."
    produces = ["vulnerability"]
    consumes = ["url_param"]
    needs_input_file = True
    allowed_params = {"workers"}
    rate_limit_rps = 30.0

    def build_argv(self, ctx: ToolContext) -> list[str]:
        params = self.validate_params(ctx.params)
        return [
            "dalfox", "file", ctx.input_file or "",
            "--json", "--no-color", "--silence",
            "--worker", str(max(1, int(params.get("workers", 10)))),
        ]

    def parse(self, result: ExecResult, ctx: ToolContext) -> list[dict]:
        findings: list[dict] = []
        for rec in _json_lines(result.stdout):
            data = rec.get("data") if isinstance(rec.get("data"), dict) else {}
            event_type = str(rec.get("type", "")).lower()
            url = str(rec.get("url") or data.get("url") or "").strip()
            # Vulnerability events carry an injected-payload proof; informational
            # events (reflection hints, etc.) are ignored to protect the FP gate.
            is_vuln = event_type in ("v", "vuln", "vulnerability") or (
                bool(data.get("injected")) and bool(url)
            )
            if not is_vuln or not url:
                continue
            findings.append({
                "type": "vulnerability",
                "id": "dalfox-xss",
                "name": f"XSS ({str(data.get('type') or 'reflected')})",
                "value": f"dalfox-xss@{url}",
                "severity": "medium",          # scanner-confirmed, human-validated later
                "matched_at": url,
                "tags": ["xss", "dalfox"],
                "evidence": {
                    "injected": data.get("injected"),
                    "payload": data.get("payload"),
                    "message": data.get("message"),
                    "crawled_from": ctx.target,
                },
            })
        return _dedupe(findings, "value")


@register
class GowitnessTool(ToolWrapper):
    """Headless screenshots of live web hosts for visual triage.

    consumes: live_host
    produces: screenshot (metadata rows pointing at PNG artifacts)

    Runtime note: requires a Chromium/Chrome binary inside the worker image
    (see the commented install block in worker/Dockerfile). When the binary
    is absent the executor fails the task cleanly and the retry/dead-letter
    machinery handles it — nothing crashes the pipeline.
    """

    name = "gowitness"
    binary = "gowitness"
    description = "Screenshot capture of live hosts for visual triage."
    produces = ["screenshot"]
    consumes = ["live_host"]
    needs_input_file = True
    allowed_params = {"timeout_secs"}
    rate_limit_rps = 5.0

    SCREENSHOT_DIR = "screenshots"

    def _out_dir(self, ctx: ToolContext) -> str:
        return os.path.join(ctx.workdir, self.SCREENSHOT_DIR)

    def build_argv(self, ctx: ToolContext) -> list[str]:
        params = self.validate_params(ctx.params)
        return [
            "gowitness", "scan", "file",
            "-f", ctx.input_file or "",
            "--screenshot-path", self._out_dir(ctx),
            "--timeout", str(int(params.get("timeout_secs", 15))),
            "--disable-http2",
        ]

    def parse(self, result: ExecResult, ctx: ToolContext) -> list[dict]:
        out_dir = self._out_dir(ctx)
        if not os.path.isdir(out_dir):
            return []
        root = ctx.target.lstrip("*.").strip().lower()
        findings: list[dict] = []
        for filename in sorted(os.listdir(out_dir)):
            lower = filename.lower()
            if not lower.endswith((".png", ".jpg", ".jpeg")):
                continue
            # gowitness names artifacts after the probed host; derive the
            # entity value from the filename stem (host[:port]).
            stem = filename.rsplit(".", 1)[0]
            findings.append({
                "type": "screenshot",
                "value": stem,
                "artifact": os.path.join(out_dir, filename),
                "host": stem,
                "source_target": ctx.target,
            })
            _ = root  # namespace retained for future cross-checks
        return findings
