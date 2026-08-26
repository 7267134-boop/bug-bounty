"""Stage 2 - subdomain enumeration wrappers (subfinder/assetfinder/amass)."""

from __future__ import annotations

import json

from .base import ExecResult, ToolContext, ToolWrapper
from .registry import register


def _json_lines(stdout: str):
    """Yield parsed objects from JSON-lines output; noise-tolerant."""
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                yield json.loads(line)
            except ValueError:
                continue


def _dedupe(findings: list[dict], key: str) -> list[dict]:
    seen: set[str] = set()
    out = []
    for f in findings:
        v = str(f.get(key, ""))
        if v and v not in seen:
            seen.add(v)
            out.append(f)
    return out


@register
class SubfinderTool(ToolWrapper):
    name = "subfinder"
    binary = "subfinder"
    description = "Fast passive subdomain enumeration across public sources."
    produces = ["subdomain"]
    consumes: list[str] = []
    allowed_params = {"all_sources"}
    rate_limit_rps = 20.0

    def build_argv(self, ctx: ToolContext) -> list[str]:
        params = self.validate_params(ctx.params)
        argv = ["subfinder", "-d", ctx.target, "-json", "-silent", "-nc"]
        if params.get("all_sources"):
            argv.append("-all")
        return argv

    def parse(self, result: ExecResult, ctx: ToolContext) -> list[dict]:
        findings = []
        for rec in _json_lines(result.stdout):
            host = str(rec.get("host", "")).strip().lower()
            if host:
                findings.append({"type": "subdomain", "subdomain": host,
                                 "source": rec.get("source") or "subfinder"})
        return _dedupe(findings, "subdomain")


@register
class AssetfinderTool(ToolWrapper):
    name = "assetfinder"
    binary = "assetfinder"
    description = "Lightweight subdomain/related-domain discovery (CT logs, DNS)."
    produces = ["subdomain"]
    consumes: list[str] = []

    def build_argv(self, ctx: ToolContext) -> list[str]:
        self.validate_params(ctx.params)
        return ["assetfinder", "--subs-only", ctx.target]

    def parse(self, result: ExecResult, ctx: ToolContext) -> list[dict]:
        findings = []
        for line in result.stdout.splitlines():
            host = line.strip().lower().rstrip(".")
            if host and "." in host and not host.startswith("-"):
                findings.append({"type": "subdomain", "subdomain": host,
                                 "source": "assetfinder"})
        return _dedupe(findings, "subdomain")


@register
class AmassTool(ToolWrapper):
    name = "amass"
    binary = "amass"
    description = "OWASP Amass passive enumeration (thorough but slow)."
    produces = ["subdomain"]
    consumes: list[str] = []
    allowed_params = {"timeout_min"}
    rate_limit_rps = 5.0

    def build_argv(self, ctx: ToolContext) -> list[str]:
        params = self.validate_params(ctx.params)
        argv = ["amass", "enum", "-passive", "-d", ctx.target, "-nc"]
        if params.get("timeout_min"):
            argv += ["-timeout", str(int(params["timeout_min"]))]
        return argv

    def parse(self, result: ExecResult, ctx: ToolContext) -> list[dict]:
        target = ctx.target.lstrip("*.").strip()
        suffix = "." + target if target else ""
        findings = []
        for line in result.stdout.splitlines():
            host = line.strip().split()[0].lower().rstrip(".") if line.strip() else ""
            if not host or "." not in host or host.startswith("[") :
                continue
            # keep only names inside the authorized namespace (amass can emit
            # related third-party domains we are NOT authorized to touch).
            if target and not (host == target or host.endswith(suffix)):
                continue
            findings.append({"type": "subdomain", "subdomain": host,
                             "source": "amass"})
        return _dedupe(findings, "subdomain")
