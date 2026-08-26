"""Stage 4 — out-of-band (OOB) interaction tooling.

    interactsh   url_param → vulnerability   (blind SSRF / OOB prover)

The wrapper drives a builtin Python collaborator client
(``drivers/interactsh.py``) implementing the projectdiscovery interactsh
protocol: register a session, inject unique callback hosts into crawled
parameter URLs, then correlate inbound interactions back to the exact
parameter that triggered them. No extra binary, no shell, everything
sandboxed and rate-limited like every other wrapper.
"""

from __future__ import annotations

import json
import os.path
import re
import sys

from .base import ExecResult, ToolContext, ToolExecutionError, ToolWrapper
from .registry import register
from .recon_enum import _dedupe

DRIVER_PATH = os.path.join(os.path.dirname(__file__), "drivers", "interactsh.py")

_SERVER_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]{2,253}$")


@register
class InteractshTool(ToolWrapper):
    """Blind-SSRF / OOB prover over an interactsh collaborator.

    consumes: url_param            produces: vulnerability (id='interactsh-oob')
    A callback hit is strong evidence (the target's server made a DNS/HTTP
    request to *our* host) but exploitation context still requires human
    triage — findings land as 'unvalidated' (Pillar B).
    """

    name = "interactsh"
    binary = ""                          # builtin driver via sys.executable
    description = ("Blind SSRF / OOB detection: injects collaborator "
                   "payloads into parameter URLs and matches interactions.")
    produces = ["vulnerability"]
    consumes = ["url_param"]
    needs_input_file = True
    allowed_params = {"server", "duration_secs", "max_urls", "request_timeout"}
    rate_limit_rps = 5.0

    DURATION_MIN, DURATION_MAX = 10, 300
    URLS_MIN, URLS_MAX = 1, 100
    TIMEOUT_MIN, TIMEOUT_MAX = 1, 30

    @staticmethod
    def _clamp(value: int, low: int, high: int) -> int:
        return max(low, min(high, value))

    def build_argv(self, ctx: ToolContext) -> list[str]:
        params = self.validate_params(ctx.params)
        server = str(params.get("server") or "oast.pro").strip().lower()
        # The host lands in argv AND in generated DNS names — charset-guard
        # it structurally (same defense style as scope targets).
        if not _SERVER_RE.match(server):
            raise ToolExecutionError(f"interactsh: illegal server host {server!r}")
        duration = self._clamp(int(params.get("duration_secs", 30)),
                               self.DURATION_MIN, self.DURATION_MAX)
        max_urls = self._clamp(int(params.get("max_urls", 25)),
                               self.URLS_MIN, self.URLS_MAX)
        request_timeout = self._clamp(int(params.get("request_timeout", 10)),
                                      self.TIMEOUT_MIN, self.TIMEOUT_MAX)
        return [
            sys.executable, DRIVER_PATH, ctx.input_file or "",
            "--server", server,
            "--duration-secs", str(duration),
            "--max-urls", str(max_urls),
            "--request-timeout", str(request_timeout),
        ]

    def parse(self, result: ExecResult, ctx: ToolContext) -> list[dict]:
        findings: list[dict] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if not rec.get("found") or not str(rec.get("url") or ""):
                continue
            url = str(rec["url"])
            protocol = str(rec.get("protocol") or "?")
            findings.append({
                "type": "vulnerability",
                "id": "interactsh-oob",
                "name": f"OOB interaction ({protocol})",
                "value": f"interactsh-oob@{url}",
                "severity": "high",
                "matched_at": url,
                "tags": ["ssrf", "oob", "interactsh"],
                "evidence": {
                    "protocol": protocol,
                    "remote_address": rec.get("remote"),
                    "unique_id": rec.get("unique-id"),
                    "timestamp": rec.get("timestamp"),
                },
            })
        return _dedupe(findings, "value")
