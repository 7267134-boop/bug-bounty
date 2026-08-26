"""Stage 2 - URL collection & vulnerability scanning wrappers."""

from __future__ import annotations

import json

from common.constants import SEVERITIES

from .base import ExecResult, ToolContext, ToolWrapper
from .registry import register
from .recon_enum import _dedupe, _json_lines

_SEV_OK = frozenset(SEVERITIES) | {"unknown"}


@register
class WaybackurlsTool(ToolWrapper):
    name = "waybackurls"
    binary = "waybackurls"
    description = "Historic URLs for hosts from the Wayback Machine (stdin mode)."
    produces = ["archive_url", "url_param", "js_url"]
    consumes = ["subdomain"]
    rate_limit_rps = 10.0

    def build_argv(self, ctx: ToolContext) -> list[str]:
        self.validate_params(ctx.params)
        return ["waybackurls"]

    def stdin_data(self, ctx: ToolContext) -> bytes | None:
        values: list[str] = []
        for ftype in self.consumes:
            values.extend(ctx.inputs.get(ftype, []))
        return ("\n".join(dict.fromkeys(values)) + "\n").encode() if values else None

    def parse(self, result: ExecResult, ctx: ToolContext) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        for line in result.stdout.splitlines():
            url = line.strip()
            if not url or " " in url or url in seen:
                continue
            seen.add(url)
            findings.append({"type": "archive_url", "value": url})
            if "?" in url:
                findings.append({"type": "url_param", "url": url, "value": url})
            if url.lower().split("?")[0].endswith(".js"):
                findings.append({"type": "js_url", "value": url})
        return findings


@register
class KatanaTool(ToolWrapper):
    name = "katana"
    binary = "katana"
    description = "Next-gen crawler (standard mode) over live URLs."
    produces = ["url", "url_param", "js_url"]
    consumes = ["live_host"]
    needs_input_file = True
    allowed_params = {"depth", "concurrency"}
    rate_limit_rps = 80.0

    def build_argv(self, ctx: ToolContext) -> list[str]:
        params = self.validate_params(ctx.params)
        return [
            "katana", "-list", ctx.input_file or "", "-json", "-silent",
            "-no-color",
            "-d", str(int(params.get("depth", 3))),
            "-c", str(int(params.get("concurrency", 10))),
            "-rl", str(int(min(ctx.rate_limit_rps * 2, 150))),
        ]

    def parse(self, result: ExecResult, ctx: ToolContext) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        for rec in _json_lines(result.stdout):
            endpoint = ""
            req = rec.get("request")
            if isinstance(req, dict):
                endpoint = str(req.get("endpoint") or "")
            endpoint = endpoint or str(rec.get("endpoint") or "")
            if not endpoint or endpoint in seen:
                continue
            seen.add(endpoint)
            findings.append({"type": "url", "value": endpoint})
            if "?" in endpoint:
                findings.append({"type": "url_param", "url": endpoint,
                                 "value": endpoint})
            if endpoint.lower().split("?")[0].endswith(".js"):
                findings.append({"type": "js_url", "value": endpoint})
        return findings


@register
class NucleiTool(ToolWrapper):
    name = "nuclei"
    binary = "nuclei"
    description = "Template-driven vulnerability scan with severity filtering."
    produces = ["vulnerability"]
    consumes = ["live_host"]
    needs_input_file = True
    allowed_params = {"severity"}
    rate_limit_rps = 30.0

    def build_argv(self, ctx: ToolContext) -> list[str]:
        params = self.validate_params(ctx.params)
        severity = str(params.get("severity", "low,medium,high,critical"))
        return [
            "nuclei", "-l", ctx.input_file or "", "-json", "-silent", "-nc",
            "-severity", severity, "-c", "25",
            "-timeout", str(max(3, min(15, max(3, ctx.timeout_secs // 60)))),
        ]

    def parse(self, result: ExecResult, ctx: ToolContext) -> list[dict]:
        findings: list[dict] = []
        for rec in _json_lines(result.stdout):
            info = rec.get("info") if isinstance(rec.get("info"), dict) else {}
            classification = info.get("classification") \
                if isinstance(info.get("classification"), dict) else {}
            severity = str(info.get("severity", "unknown")).lower()
            template_id = (rec.get("template-id") or rec.get("templateID")
                           or info.get("name") or "unknown")
            matched_at = rec.get("matched-at") or rec.get("matched") or rec.get("host")
            findings.append({
                "type": "vulnerability",
                "id": template_id,
                "name": info.get("name") or template_id,
                # composite value => one fingerprint per (template, match target)
                "value": f"{template_id}@{matched_at}",
                "severity": severity if severity in _SEV_OK else "unknown",
                "matched_at": matched_at,
                "description": info.get("description"),
                "tags": info.get("tags") or [],
                "cve_ids": classification.get("cve-id") or [],
                "cvss_score": classification.get("cvss-score"),
            })
        return _dedupe(findings, "value")


@register
class UncoverTool(ToolWrapper):
    """Shodan/Censys/FOFA/... exposure search (requires provider config).

    Provider API keys come from the standard uncover config mounted at
    ``$HOME/.config/uncover/provider-config.yaml``. Results are strictly
    filtered to the authorized namespace before ingestion.
    """

    name = "uncover"
    binary = "uncover"
    description = "Multi-engine exposed-host search (Shodan/Censys/...)."
    produces = ["subdomain", "open_port"]
    consumes: list[str] = []
    allowed_params = {"providers"}
    rate_limit_rps = 5.0

    def build_argv(self, ctx: ToolContext) -> list[str]:
        params = self.validate_params(ctx.params)
        argv = ["uncover", "-q", ctx.target, "-json", "-silent"]
        if params.get("providers"):
            argv += ["-e", str(params["providers"])]
        return argv

    @staticmethod
    def _in_scope(host: str, root: str) -> bool:
        if not root:
            return False
        host = host.lower().rstrip(".")
        return host == root or host.endswith("." + root)

    def parse(self, result: ExecResult, ctx: ToolContext) -> list[dict]:
        import ipaddress

        root = ctx.target.lstrip("*.").strip().lower()
        findings: list[dict] = []
        for rec in _json_lines(result.stdout):
            host = str(rec.get("host") or "").strip().lower()
            ip = str(rec.get("ip") or "").strip()
            port = rec.get("port")
            try:
                bare_ip = bool(ipaddress.ip_address(host or ip))
            except ValueError:
                bare_ip = False
            named_in_scope = bool(host and "." in host and self._in_scope(host, root))
            if named_in_scope:
                findings.append({"type": "subdomain", "subdomain": host,
                                 "source": rec.get("source") or "uncover"})
            if isinstance(port, int) and (named_in_scope or (bare_ip and not host)):
                value_host = host if named_in_scope else ip
                findings.append({
                    "type": "open_port",
                    "value": f"{value_host}:{port}",
                    "host": value_host,
                    "port": port,
                    "source": rec.get("source") or "uncover",
                })
        return _dedupe(findings, "value")

