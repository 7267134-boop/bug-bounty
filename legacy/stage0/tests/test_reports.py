"""Integration tests: report generation + pipeline behavior.

Key acceptance test: even when one tool is mocked to fail 100% of the time,
both JSON and Markdown reports are generated (spec pass criteria).
"""

import json
import os

import pytest

from recon.reports import ReportGenerator
from recon.runner import DiskFullError, write_text_file


def _sample_report() -> dict:
    results = [
        {
            "target": "example.com", "tool_name": "subfinder",
            "execution_time_sec": 1.5, "status": "success",
            "findings": [
                {"type": "subdomain", "subdomain": "api.example.com"},
                {"type": "subdomain", "subdomain": "www.example.com"},
            ],
            "raw_log_reference": "/tmp/subfinder.log", "retries_used": 1,
            "return_code": 0, "error_summary": "",
        },
        {
            "target": "example.com", "tool_name": "nmap",
            "execution_time_sec": 42.0, "status": "failed",
            "findings": [], "raw_log_reference": "/tmp/nmap.log",
            "retries_used": 3, "return_code": 1,
            "error_summary": "exit code 1",
        },
        {
            "target": "example.com", "tool_name": "nuclei",
            "execution_time_sec": 9.0, "status": "success",
            "findings": [
                {"type": "vulnerability", "id": "CVE-2024-1234",
                 "name": "Test RCE", "severity": "critical",
                 "matched_at": "https://api.example.com/", "description": "bad",
                 "tags": ["cve", "rce"], "cve_ids": ["CVE-2024-1234"],
                 "cwe_ids": [], "cvss_score": 9.8,
                 "reference_urls": ["https://example.org/ref"],
                 "curl_command": None, "source_target": "example.com"},
            ],
            "raw_log_reference": "/tmp/nuclei.log", "retries_used": 1,
            "return_code": 0, "error_summary": "",
        },
    ]
    vulns = [f for r in results for f in r["findings"] if f.get("type") == "vulnerability"]
    return {
        "schema_version": "1.0", "generated_at": "2026-08-25T12:00:00",
        "target_domain": "example.com", "config": {"dry_run": False},
        "metrics": {
            "tools_total": 3, "tools_success": 2, "tools_failed": 1,
            "tools_skipped": 0, "total_execution_time_sec": 52.5,
            "retry_counts": {"nmap": 3}, "findings_count": 4,
            "vulnerabilities_count": 1,
            "vulnerabilities_by_severity": {"critical": 1},
        },
        "results": results, "vulnerabilities": vulns,
    }


class TestReportGenerator:
    def test_dual_reports_written(self, tmp_path):
        gen = ReportGenerator(str(tmp_path), "2026-08-25T12:00:00")
        report = _sample_report()
        json_path = gen.write_json(report)
        md_path = gen.write_markdown(report)

        assert os.path.basename(json_path) == "example.com_20260825_120000_full_log.json"
        assert os.path.basename(md_path) == "example.com_20260825_120000_summary.md"

        data = json.loads(open(json_path, encoding="utf-8").read())
        assert data["metrics"]["tools_failed"] == 1
        assert len(data["results"]) == 3

        md = open(md_path, encoding="utf-8").read()
        assert "# Recon Report - example.com" in md
        assert "[CRITICAL] Test RCE" in md
        assert "Remediation:" in md          # remediation advice present
        assert "FAILED" in md                # failed tool surfaced
        assert "api.example.com" in md       # subdomains listed

    def test_empty_report_renders(self, tmp_path):
        gen = ReportGenerator(str(tmp_path), "2026-08-25T12:00:00")
        report = {
            "schema_version": "1.0", "generated_at": "2026-08-25T12:00:00",
            "target_domain": "empty.com", "config": {},
            "metrics": {}, "results": [], "vulnerabilities": [],
        }
        md_path = gen.write_markdown(report)
        md = open(md_path, encoding="utf-8").read()
        assert "*None detected.*" in md


class TestDiskFull:
    def test_write_failure_raises_diskfull(self, tmp_path):
        # Writing *inside* a path that is actually a file fails on all OSes.
        blocker = tmp_path / "blocker.txt"
        blocker.write_text("i am a file, not a directory")
        bogus = str(blocker / "child.txt")
        with pytest.raises(DiskFullError):
            write_text_file(bogus, "data")


class TestPipelineWithMockedFailure:
    """Full engine run using a fake tool spec that always fails."""

    def test_reports_generated_despite_failure(self, tmp_path, monkeypatch):
        import sys as _sys

        from recon.config import ScanConfig
        from recon.engine import ReconOrchestrator
        from recon.tools import ToolSpec

        failing = ToolSpec(
            name="alwaysfails", binary=_sys.executable,
            description="mock tool that fails every attempt", stage=1,
            parser_name=None,
            build_args=lambda config, ctx: ["-c", "import sys; sys.exit(1)"],
        )
        monkeypatch.setattr("recon.engine.expand_tool_selection", lambda tools: [failing])

        cfg = ScanConfig(
            target_domain="example.com", enabled_tools=["all"], max_retries=2,
            retry_delay_sec=0.01, output_dir=str(tmp_path),
        )
        report = asyncio_run(ReconOrchestrator(cfg).run())

        assert report["metrics"]["tools_failed"] == 1
        out = report["output_files"]
        assert os.path.isfile(out["json_report"])
        assert os.path.isfile(out["markdown_summary"])
        # Raw log preserved despite total failure (100% retention rule).
        raw = report["results"][0]["raw_log_reference"]
        assert raw and os.path.isfile(raw)

    def test_engine_graceful_disk_error(self, tmp_path, monkeypatch):
        import sys as _sys

        from recon.config import ScanConfig
        from recon.engine import ReconOrchestrator
        from recon.tools import ToolSpec

        def boom(_self, _report):
            raise DiskFullError("simulated disk full")

        monkeypatch.setattr(ReportGenerator, "write_json", boom)
        ok_tool = ToolSpec(
            name="ok_tool", binary=_sys.executable, description="d", stage=1,
            build_args=lambda config, ctx: ["-c", "pass"],
        )
        monkeypatch.setattr("recon.engine.expand_tool_selection", lambda tools: [ok_tool])
        cfg = ScanConfig(target_domain="a.com", enabled_tools=["all"],
                         output_dir=str(tmp_path))
        with pytest.raises(DiskFullError):
            asyncio_run(ReconOrchestrator(cfg).run())


def asyncio_run(coro):
    import asyncio

    return asyncio.run(coro)


