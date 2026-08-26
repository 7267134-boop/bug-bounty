"""Stage 6 — report generation (pure functions, no I/O).

Consumes ONLY validated + new findings (Pillar B: reports never surface
unvalidated noise; Pillar A cost model: state diffing already filtered
repeats upstream). Produces a typed JSON report and a Markdown rendering
with CVSS scoring and safe PoC cURL commands.

Safety invariant: finding values originated from scope-validated targets,
but report output is often pasted into a human terminal — every URL is
charset-allowlisted before being embedded in a shell command, and anything
that fails the check ships WITHOUT a PoC instead of a dangerous one.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

REPORT_VERSION = 1

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Allowlist for URLs embedded into cURL single-quoted strings: no quotes,
# no shell metacharacters ($ ` ; | & < > \ whitespace). $ is excluded even
# though single-quotes neutralize it — reports get pasted into other contexts.
_SAFE_URL_RE = re.compile(r"^https?://[A-Za-z0-9.\-_~:/?#\[\]@!&()*+,;=%]+$")
_URL_ANYWHERE_RE = re.compile(r"https?://[^\s'\"<>`$]+")

_CORS_ORIGIN = "https://cors-probe.example"


def cvss_of(finding: dict) -> tuple[float | None, str | None]:
    """(score, vector) — reported only when a tool actually computed it."""
    score = finding.get("cvss_score")
    vector = finding.get("cvss_vector")
    if score is None:
        evidence = finding.get("evidence") or {}
        if isinstance(evidence, dict):
            score = evidence.get("cvss_score")
            vector = vector or evidence.get("cvss_vector")
    try:
        score = float(score) if score is not None else None
    except (TypeError, ValueError):
        score = None
    return score, (str(vector) if vector else None)


def _extract_url(finding: dict) -> tuple[str | None, str]:
    """(url_or_None, source_field_used).

    Rejects sources where suspicious trailing material follows the URL —
    a value like ``https://x.com/?q='; rm -rf /'`` yields NO usable URL.
    """
    for key in ("matched_at", "value"):
        source = str(finding.get(key) or "")
        match = _URL_ANYWHERE_RE.search(source)
        if match:
            trailing = source[match.end():].strip()
            if any(c in source for c in "`;$") or trailing:
                continue
            return match.group(0), key
    return None, ""


def poc_curl(finding: dict) -> str | None:
    """One reproducible cURL command, or None when none can be proven safe."""
    ftype = str(finding.get("type") or "")
    if ftype == "secret":
        return None                     # secrets are not request-reproducible
    url, _ = _extract_url(finding)
    if not url or not _SAFE_URL_RE.match(url):
        return None
    if ftype == "cors_misconfig":
        return (f"curl -sk -i -H 'Origin: {_CORS_ORIGIN}' '{url}' "
                f"# inspect 'access-control-allow-origin' in response")
    return f"curl -sk -i '{url}'"


def executive_summary(findings: list[dict]) -> dict:
    by_severity = {s: 0 for s in SEVERITY_ORDER}
    for finding in findings:
        severity = str(finding.get("severity") or "info").lower()
        by_severity[severity] = by_severity.get(severity, 0) + 1
    critical, high = by_severity["critical"], by_severity["high"]
    if total := len(findings):
        if critical:
            posture = ("URGENT: critical, human-validated findings require "
                       "immediate remediation and bounty submission.")
        elif high:
            posture = ("Elevated risk: high-severity validated findings "
                       "warrant prompt reporting.")
        elif by_severity["medium"] or by_severity["low"]:
            posture = "Moderate: lower-impact validated findings to triage into reports."
        else:
            posture = "Informational-only delta this scan."
        headline = f"{total} new validated finding(s)."
    else:
        headline = "No new validated findings this scan."
        posture = "Nothing actionable — the attack surface did not change."
    return {
        "total_findings": len(findings),
        "by_severity": {k: v for k, v in by_severity.items()},
        "headline": headline,
        "posture": posture,
    }


def build_report(material: dict, generated_at: datetime | None = None) -> dict:
    """Typed report from ``database.report_material`` output."""
    scan = material.get("scan") or {}
    # Defense in depth: sort here too — never trust upstream row order,
    # even though the SQL already orders by severity.
    findings_in = sorted(
        material.get("findings") or [],
        key=lambda f: (SEVERITY_ORDER.get(
            str(f.get("severity") or "info").lower(), 4),
            str(f.get("type") or ""), str(f.get("finding_id") or "")))
    findings: list[dict] = []
    for rank, finding in enumerate(findings_in, start=1):
        score, vector = cvss_of(finding)
        findings.append({
            "rank": rank,
            "finding_id": finding.get("finding_id"),
            "type": finding.get("type"),
            "severity": (finding.get("severity") or "info").lower(),
            "cvss_score": score,
            "cvss_vector": vector,
            "name": finding.get("name") or finding.get("type"),
            "value": finding.get("value"),
            "matched_at": finding.get("matched_at"),
            "poc_curl": poc_curl(finding),
            "tags": finding.get("tags") or [],
            "evidence": finding.get("evidence") or {},
            "confidence": float(finding["confidence"])
            if finding.get("confidence") is not None else None,
            "first_seen": str(finding.get("first_seen") or ""),
        })
    generated = (generated_at or datetime.now(timezone.utc)).isoformat()
    return {
        "report_version": REPORT_VERSION,
        "generated_at": generated,
        "filters": {"validation_state": "validated", "is_new": True},
        "scan": {
            "scan_id": scan.get("scan_id"),
            "workflow": scan.get("workflow"),
            "status": scan.get("status"),
            "requested_by": scan.get("requested_by"),
            "created_at": str(scan.get("created_at") or ""),
        },
        "executive_summary": executive_summary(findings),
        "findings": findings,
    }


def to_markdown(report: dict) -> str:
    """Human-ready Markdown rendering of a built report."""
    scan = report["scan"]
    summary = report["executive_summary"]
    lines: list[str] = [
        f"# Bug Bounty Report — {scan.get('workflow')} scan",
        "",
        f"* **Scan ID**: `{scan.get('scan_id')}`",
        f"* **Generated**: {report['generated_at']}",
        f"* **Scan status**: {scan.get('status')}",
        f"* **Scope of this report**: only findings that are both "
        f"human-`validated` and new (never seen in earlier scans).",
        "",
        "## Executive Summary",
        "",
        summary["headline"],
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for severity, count in summary["by_severity"].items():
        lines.append(f"| {severity} | {count} |")
    lines += ["", f"**Posture**: {summary['posture']}", ""]

    if not report["findings"]:
        lines += ["## Findings", "", "_No actionable findings._"]
        return "\n".join(lines) + "\n"

    lines.append("## Findings")
    for finding in report["findings"]:
        cvss = finding["cvss_score"]
        cvss_txt = ""
        if cvss is not None:
            vector = f" ({finding['cvss_vector']})" if finding["cvss_vector"] else ""
            cvss_txt = f" — CVSS {cvss}{vector}"
        title = finding.get("name") or finding.get("type")
        lines += [
            "",
            f"### #{finding['rank']} [{finding['severity'].upper()}] "
            f"{title}{cvss_txt}",
            "",
            f"* **Type**: `{finding['type']}`",
            f"* **Entity**: `{finding['value']}`",
        ]
        if finding.get("matched_at"):
            lines.append(f"* **Matched at**: {finding['matched_at']}")
        if finding.get("tags"):
            lines.append("* **Tags**: " + ", ".join(
                f"`{t}`" for t in finding["tags"]))
        poc = finding.get("poc_curl")
        if poc:
            lines += ["", "**PoC (reproduce):**", "", "```bash",
                      poc, "```"]
        elif finding["type"] == "secret":
            evidence = finding.get("evidence") or {}
            preview = evidence.get("redacted_preview") or ""
            lines += ["", "**Note:** secret material is never included in "
                          "reports — rotate the credential at the source."]
            if preview:
                lines.append(f"* Redacted preview: `{preview}…`")
    return "\n".join(lines) + "\n"