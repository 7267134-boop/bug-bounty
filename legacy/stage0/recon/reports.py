"""Dual-Report Generator.

Consumes aggregated pipeline data and emits:
  * ``{domain}_{timestamp}_full_log.json`` - machine-parseable full log
  * ``{domain}_{timestamp}_summary.md``   - human-readable Markdown summary
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

from .runner import write_text_file

# Generic remediation hints keyed by nuclei tag / finding type.
REMEDIATION_HINTS: list[tuple[tuple[str, ...], str]] = [
    (
        ("cve", "critical", "rce", "exec"),
        "Patch immediately: update the affected component to the latest vendor release, "
        "check public exploit availability, and review access logs for signs of exploitation.",
    ),
    (
        ("sqli", "injection"),
        "Use parameterized queries / prepared statements, validate all user input "
        "server-side, and deploy WAF rules as a temporary mitigation.",
    ),
    (
        ("xss",),
        "Apply context-aware output encoding, adopt a strict Content-Security-Policy, "
        "and sanitize untrusted input before rendering.",
    ),
    (
        ("exposure", "config", "panel", "default-login"),
        "Restrict exposure of administrative interfaces (IP allow-listing / VPN), "
        "enforce strong authentication, and remove default credentials.",
    ),
    (
        ("ssl", "tls", "misconfiguration"),
        "Enable modern TLS configuration (TLS 1.2+), disable weak ciphers, redirect "
        "HTTP to HTTPS, and add HSTS headers.",
    ),
    (
        ("subdomain", "takeover"),
        "Remove dangling DNS records pointing to deprovisioned services and re-register "
        "or reclaim the affected resource.",
    ),
]


def _remediation(finding: dict[str, Any]) -> str:
    tags = [str(t).lower() for t in finding.get("tags", [])] + [str(finding.get("type", "")).lower()]
    for keys, hint in REMEDIATION_HINTS:
        if any(k in tags or k in str(finding.get("id", "")).lower() for k in keys):
            return hint
    return "Review the finding details and consult the referenced template/documentation."


class ReportGenerator:
    """Writes the JSON full-log and Markdown summary reports."""

    def __init__(self, output_dir: str, timestamp: str):
        self.output_dir = os.path.abspath(output_dir)
        # Filesystem-safe timestamp: 20260825_143001
        self.stamp = re.sub(r"[:\-]", "", timestamp.replace("T", "_"))
        os.makedirs(self.output_dir, exist_ok=True)
        self.report_domain = "unknown"

    def _safe_domain(self) -> str:
        return re.sub(r"[^A-Za-z0-9._-]", "_", self.report_domain)

    @property
    def json_path(self) -> str:
        return os.path.join(self.output_dir, f"{self._safe_domain()}_{self.stamp}_full_log.json")

    @property
    def markdown_path(self) -> str:
        return os.path.join(self.output_dir, f"{self._safe_domain()}_{self.stamp}_summary.md")

    def write_json(self, report: dict[str, Any]) -> str:
        self.report_domain = str(report.get("target_domain", "unknown"))
        payload = json.dumps(report, indent=2, ensure_ascii=False, default=str)
        write_text_file(self.json_path, payload)
        return self.json_path

    def write_markdown(self, report: dict[str, Any]) -> str:
        self.report_domain = str(report.get("target_domain", "unknown"))
        write_text_file(self.markdown_path, self._render_markdown(report))
        return self.markdown_path

    # ------------------------------------------------------------------ #
    def _render_markdown(self, report: dict[str, Any]) -> str:
        m = report.get("metrics", {})
        lines: list[str] = []
        ap = lines.append

        ap(f"# Recon Report - {report['target_domain']}")
        ap("")
        ap(f"*Generated:* {report['generated_at']}  ")
        ap(f"*Tools executed:* {m.get('tools_total', 0)} "
           f"(success: {m.get('tools_success', 0)}, failed: {m.get('tools_failed', 0)}, "
           f"skipped: {m.get('tools_skipped', 0)})  ")
        ap(f"*Total findings:* {m.get('findings_count', 0)}  ")
        ap(f"*Vulnerabilities:* {m.get('vulnerabilities_count', 0)}")
        ap("")

        ap("## High-Level Metrics")
        ap("")
        ap("| Metric | Value |")
        ap("|---|---|")
        ap(f"| Target domain | `{report['target_domain']}` |")
        ap(f"| Total execution time | {m.get('total_execution_time_sec', 0):.1f}s |")
        for sev in ("critical", "high", "medium", "low", "info"):
            count = m.get("vulnerabilities_by_severity", {}).get(sev, 0)
            if count:
                ap(f"| {sev.capitalize()} vulnerabilities | {count} |")
        retried = {k: v for k, v in m.get("retry_counts", {}).items() if v > 1}
        if retried:
            ap(f"| Tools that used retries | {', '.join(sorted(retried))} |")
        ap("")

        ap("## Critical & High Findings")
        ap("")
        vulns = [v for v in report.get("vulnerabilities", [])
                 if v.get("severity") in ("critical", "high")]
        if not vulns:
            ap("*None detected.*")
        else:
            for v in vulns:
                ap(f"### [{str(v.get('severity')).upper()}] {v.get('name')} (`{v.get('id')}`)")
                ap("")
                ap(f"- **Matched at:** {v.get('matched_at')}")
                if v.get("description"):
                    ap(f"- **Description:** {v['description']}")
                if v.get("cve_ids"):
                    ap(f"- **CVEs:** {', '.join(map(str, v['cve_ids']))}")
                refs = v.get("reference_urls") or []
                if refs:
                    ap(f"- **References:** {'; '.join(map(str, refs))}")
                ap(f"- **Remediation:** {_remediation(v)}")
                ap("")

        others = [v for v in report.get("vulnerabilities", [])
                  if v.get("severity") not in ("critical", "high")]
        ap("## Medium / Low / Info Findings")
        ap("")
        if not others:
            ap("*None detected.*")
        else:
            ap("| Severity | Finding | Matched at |")
            ap("|---|---|---|")
            for v in others:
                ap(f"| {v.get('severity')} | {v.get('name')} (`{v.get('id')}`) "
                   f"| {v.get('matched_at')} |")
        ap("")

        # ---- Attack surface ----
        subs, live, ports, hosts = [], [], [], []
        for r in report.get("results", []):
            for f in r.get("findings", []):
                t = f.get("type")
                if t == "subdomain":
                    subs.append(f["subdomain"])
                elif t == "live_host":
                    status = f.get("status_code") or "?"
                    title = f.get("title") or ""
                    live.append(f"- [{f['url']}]({f['url']}) - HTTP {status} {title}".rstrip())
                elif t == "open_port":
                    ports.append(f"{f['host']}:{f['port']}")
                elif t == "host_ports":
                    for p in f.get("ports", []):
                        svc = p.get("service", "")
                        ver = p.get("version", "")
                        hosts.append(
                            f"- {f['host']}:{p['port']}/{p.get('protocol', 'tcp')} {svc} {ver}".rstrip()
                        )

        ap("## Discovered Subdomains")
        ap("")
        ap(", ".join(f"`{s}`" for s in sorted(subs)) if subs else "*None.*")
        ap("")
        ap("## Live Web Hosts")
        ap("")
        lines.extend(live) if live else ap("*None.*")
        ap("")
        ap("## Open Ports / Services")
        ap("")
        if hosts or ports:
            lines.extend(hosts)
            if ports:
                ap(f"- naabu: {', '.join(sorted(set(ports)))}")
        else:
            ap("*None.*")
        ap("")

        ap("## Tool Execution Summary")
        ap("")
        ap("| Tool | Status | Time (s) | Retries | Findings | Raw log |")
        ap("|---|---|---|---|---|---|")
        icon = {"success": "OK", "failed": "FAILED", "skipped": "SKIPPED"}
        for r in report.get("results", []):
            raw = r.get("raw_log_reference", "")
            raw_disp = f"`{os.path.basename(raw)}`" if raw else "-"
            ap(
                f"| {r.get('tool_name')} | {icon.get(r.get('status'), r.get('status'))} "
                f"| {r.get('execution_time_sec', 0):.1f} | {r.get('retries_used', 0)} "
                f"| {len(r.get('findings', []))} | {raw_disp} |"
            )
        ap("")

        failed = [r for r in report.get("results", []) if r.get("status") == "failed"]
        if failed:
            ap("## Failed Tools (pipeline continued)")
            ap("")
            for r in failed:
                ap(f"- **{r['tool_name']}**: {r.get('error_summary', 'unknown failure')} "
                   f"(after {r.get('retries_used', 0)} attempts)")
            ap("")

        ap("---")
        ap(f"_Machine-readable full log: `{os.path.basename(self.json_path)}`_")
        ap("")
        return "\n".join(lines)


def generate_all(output_dir: str, report: dict[str, Any]) -> tuple[str, str]:
    """Convenience wrapper returning (json_path, markdown_path)."""
    gen = ReportGenerator(output_dir, report["generated_at"])
    return gen.write_json(report), gen.write_markdown(report)

