"""Stage 6 tests: report builder, Markdown renderer, PoC safety, DB layer,
Master API endpoint."""

from datetime import datetime, timezone

import pytest

from common.db import report_material
from common.testing import FakePool, row
from master.reporting import (build_report, cvss_of, executive_summary,
                              poc_curl, to_markdown)

SCAN_ID = "55555555-5555-5555-5555-555555555555"


def _material(findings: list[dict] | None = None) -> dict:
    return {
        "scan": {"scan_id": SCAN_ID, "workflow": "deep-recon",
                 "status": "completed", "requested_by": "tester",
                 "created_at": "2026-01-01T00:00:00+00:00"},
        "findings": findings or [],
    }


def _finding(**over):
    base = {
        "finding_id": "f1", "type": "vulnerability", "value": "x",
        "severity": "high", "confidence": 0.9,
        "first_seen": datetime(2026, 1, 2, tzinfo=timezone.utc),
    }
    base.update(over)
    return base


# --------------------------------------------------------------------- #
# CVSS extraction                                                        #
# --------------------------------------------------------------------- #
class TestCvss:
    def test_top_level_score_and_vector(self):
        assert cvss_of({"cvss_score": 9.1, "cvss_vector": "CVSS:3.1/AV:N"}) \
            == (9.1, "CVSS:3.1/AV:N")

    def test_score_from_evidence(self):
        assert cvss_of({"evidence": {"cvss_score": "7.5"}}) == (7.5, None)

    def test_garbage_score_is_none_not_crash(self):
        assert cvss_of({"cvss_score": "not-a-number"}) == (None, None)

    def test_absent(self):
        assert cvss_of({}) == (None, None)


# --------------------------------------------------------------------- #
# PoC cURL safety                                                        #
# --------------------------------------------------------------------- #
class TestPocSafety:
    def test_plain_url_gets_simple_poc(self):
        poc = poc_curl({"type": "vulnerability",
                        "matched_at": "https://x.com/admin"})
        assert poc == "curl -sk -i 'https://x.com/admin'"

    def test_shell_injection_in_url_yields_no_poc(self):
        for evil in ("https://x.com/?q='; rm -rf /'",
                     "https://x.com/?a=`id`",
                     "https://x.com/$(whoami)",
                     "not a url; rm -rf /"):
            assert poc_curl({"type": "vulnerability", "matched_at": evil}) \
                is None, evil

    def test_secret_never_gets_a_request_poc(self):
        finding = {"type": "secret", "matched_at": "https://x.com/app.js"}
        assert poc_curl(finding) is None

    def test_cors_poc_uses_origin_header(self):
        poc = poc_curl({"type": "cors_misconfig",
                        "value": "cors misconfigured at https://api.x.com/v1"})
        assert poc is not None and "-H 'Origin:" in poc \
            and "'https://api.x.com/v1'" in poc

    def test_url_extracted_from_value_when_no_match(self):
        poc = poc_curl({"type": "vulnerability",
                        "value": "interactsh-oob@https://t.com/?q=1"})
        assert poc == "curl -sk -i 'https://t.com/?q=1'"


# --------------------------------------------------------------------- #
# Report structure                                                       #
# --------------------------------------------------------------------- #
class TestBuildReport:
    def test_filters_block_is_explicit(self):
        report = build_report(_material())
        assert report["filters"] == {"validation_state": "validated",
                                     "is_new": True}

    def test_severity_ordering_critical_first(self):
        findings = [_finding(finding_id="c", severity="critical"),
                    _finding(finding_id="l", severity="low"),
                    _finding(finding_id="h", severity="high")]
        report = build_report(_material(list(reversed(findings))))
        ranks = [f["severity"] for f in report["findings"]]
        assert ranks == ["critical", "high", "low"]
        assert [f["rank"] for f in report["findings"]] == [1, 2, 3]

    def test_executive_summary_counts(self):
        summary = executive_summary([
            {"severity": "critical"}, {"severity": "critical"},
            {"severity": "high"}, {"severity": "info"}])
        assert summary["total_findings"] == 4
        assert summary["by_severity"]["critical"] == 2
        assert "URGENT" in summary["posture"]

    def test_empty_scan_posture(self):
        summary = executive_summary([])
        assert summary["total_findings"] == 0
        assert "No new validated" in summary["headline"]

    def test_unknown_severity_defaults_info(self):
        report = build_report(_material([_finding(severity=None)]))
        assert report["findings"][0]["severity"] == "info"


# --------------------------------------------------------------------- #
# Markdown renderer                                                      #
# --------------------------------------------------------------------- #
class TestMarkdown:
    def _report(self, findings=None):
        return build_report(_material(findings),
                            generated_at=datetime(2026, 1, 3,
                                                  tzinfo=timezone.utc))

    def test_contains_core_sections(self):
        md = to_markdown(self._report([
            _finding(name="XSS reflected",
                     matched_at="https://x.com/?q=1",
                     tags=["xss"], evidence={"payload": "<svg>"}),
            _finding(type="secret", value="secret:AWS:/js/app.js",
                     severity="critical", name="AWS key",
                     evidence={"redacted_preview": "AKIAIOSFODNN"}),
        ]))
        assert "# Bug Bounty Report — deep-recon scan" in md
        assert "## Executive Summary" in md
        assert "| critical | 1 |" in md
        assert "### #1" in md and "XSS reflected" in md
        assert "```bash" in md and "curl -sk -i 'https://x.com/?q=1'" in md
        # secrets: redacted note only, never the full material
        assert "rotate the credential" in md
        assert "AKIAIOSFODNN…" in md

    def test_empty_findings_renders_placeholder(self):
        md = to_markdown(self._report())
        assert "_No actionable findings._" in md


# --------------------------------------------------------------------- #
# DB materialization (FakePool)                                          #
# --------------------------------------------------------------------- #
class TestReportMaterial:
    def test_filters_and_metadata_enrichment(self):
        import json

        scan_row = row(scan_id=SCAN_ID, workflow="recon", status="completed",
                       created_at="now", requested_by="tester")
        finding_rows = [
            row(finding_id="f1", type="vulnerability",
                value="dalfox-xss@https://x.com/?q=1", severity="high",
                confidence=0.9, first_seen="t1",
                metadata=json.dumps({"name": "XSS reflected",
                                     "matched_at": "https://x.com/?q=1",
                                     "tags": ["xss"], "cvss_score": 8.2})),
            row(finding_id="f2", type="secret", value="secret:AWS:x",
                severity="critical", confidence=None, first_seen="t2",
                metadata={"evidence": {"redacted_preview": "AKIA"}}),
        ]
        pool = FakePool({
            "from scans s": [scan_row],
            "validation_state = 'validated'": finding_rows,
        })
        material = asyncio_run(report_material(pool, SCAN_ID))
        assert material["scan"]["workflow"] == "recon"
        f1 = next(f for f in material["findings"]
                  if f["finding_id"] == "f1")
        assert f1["name"] == "XSS reflected"          # lifted from metadata
        assert f1["cvss_score"] == 8.2
        assert isinstance(f1["metadata"], dict)
        f2 = next(f for f in material["findings"]
                  if f["finding_id"] == "f2")
        assert f2["metadata"]["evidence"]["redacted_preview"] == "AKIA"

    def test_string_metadata_json_tolerated(self):
        pool = FakePool({
            "from scans s": [row(scan_id=SCAN_ID, workflow="w",
                                 status="completed", created_at="c",
                                 requested_by="r")],
            "validation_state = 'validated'": [
                row(finding_id="f", type="vulnerability", value="v",
                    severity="high", confidence=None, first_seen="t",
                    metadata="{not-json}")],
        })
        material = asyncio_run(report_material(pool, SCAN_ID))
        assert material["findings"][0]["metadata"] == {}   # degraded, not fatal

    def test_unknown_scan_returns_none(self):
        pool = FakePool()   # nothing canned -> fetchrow None
        assert asyncio_run(report_material(pool, SCAN_ID)) is None


def asyncio_run(coro):
    import asyncio
    return asyncio.run(coro)


# --------------------------------------------------------------------- #
# Master API endpoint                                                    #
# --------------------------------------------------------------------- #
from master import api as master_api  # noqa: E402


class TestReportEndpoint:
    def _material(self):
        return _material([
            _finding(name="XSS", matched_at="https://x.com/?q=1"),
        ])

    @staticmethod
    def _fake(sync_result):
        async def _fn(pool, sid):
            return sync_result
        return _fn

    def test_requires_token(self, api_client):
        res = api_client.get(f"/api/v1/scans/{SCAN_ID}/report")
        assert res.status_code == 401

    def test_json_report_shape(self, api_client, monkeypatch):
        monkeypatch.setattr(master_api.database, "report_material",
                            self._fake(self._material()))
        res = api_client.get(f"/api/v1/scans/{SCAN_ID}/report",
                             headers={"X-API-Token": "test-token"})
        assert res.status_code == 200
        body = res.json()
        assert body["scan"]["scan_id"] == SCAN_ID
        assert body["filters"]["validation_state"] == "validated"
        assert body["findings"][0]["poc_curl"].startswith("curl")

    def test_md_report_content_type(self, api_client, monkeypatch):
        monkeypatch.setattr(master_api.database, "report_material",
                            self._fake(self._material()))
        res = api_client.get(f"/api/v1/scans/{SCAN_ID}/report?format=md",
                             headers={"X-API-Token": "test-token"})
        assert res.status_code == 200
        assert res.headers["content-type"].startswith("text/markdown")
        assert "# Bug Bounty Report" in res.text

    def test_bad_format_400(self, api_client, monkeypatch):
        monkeypatch.setattr(master_api.database, "report_material",
                            self._fake(self._material()))
        res = api_client.get(f"/api/v1/scans/{SCAN_ID}/report?format=html",
                             headers={"X-API-Token": "test-token"})
        assert res.status_code == 400

    def test_unknown_scan_404(self, api_client, monkeypatch):
        monkeypatch.setattr(master_api.database, "report_material",
                            self._fake(None))
        res = api_client.get(f"/api/v1/scans/{SCAN_ID}/report",
                             headers={"X-API-Token": "test-token"})
        assert res.status_code == 404