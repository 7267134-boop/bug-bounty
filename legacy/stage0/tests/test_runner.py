"""Tests for ToolRunner resiliency: retries, timeouts, raw-log preservation.

Uses real subprocesses (sys.executable) so the asyncio code paths are fully
exercised without requiring Kali tools to be installed.
"""

import asyncio
import os
import sys

from recon.config import ScanConfig
from recon.runner import ToolRunner, write_text_file
from recon.tools import ToolSpec


def make_config(tmp_path, **kw):
    defaults = dict(
        target_domain="example.com",
        max_retries=3,
        tool_timeout_sec=30,
        retry_delay_sec=0.01,
        output_dir=str(tmp_path),
    )
    defaults.update(kw)
    return ScanConfig(**defaults)


def make_spec(binary, args, name="faketool", parser_name=None):
    return ToolSpec(
        name=name,
        binary=binary,
        description="test tool",
        stage=1,
        parser_name=parser_name,
        build_args=lambda config, ctx: args,
    )


class TestAlwaysFailingTool:
    """Pass criterion: a tool failing 100% of the time is retried 3x, logged,
    marked failed - and the pipeline can still produce reports."""

    def test_retries_three_times_then_fails(self, tmp_path):
        spec = make_spec(sys.executable, ["-c", "import sys; sys.exit(1)"])
        cfg = make_config(tmp_path)
        runner = ToolRunner(spec, cfg, str(tmp_path / "logs"))
        result = asyncio.run(runner.run({"files": {}}))

        assert result.status == "failed"
        assert result.retries_used == 3          # exactly max_retries attempts
        assert result.findings == []
        assert result.error_summary != ""
        # Raw log MUST exist and record all three attempts.
        assert os.path.isfile(result.raw_log_reference)
        content = open(result.raw_log_reference, encoding="utf-8").read()
        assert content.count("attempt") == 3

    def test_binary_not_found(self, tmp_path):
        spec = make_spec("definitely-not-a-real-binary-xyz", [])
        cfg = make_config(tmp_path)
        runner = ToolRunner(spec, cfg, str(tmp_path / "logs"))
        result = asyncio.run(runner.run({"files": {}}))
        assert result.status == "failed"
        assert "not found" in result.error_summary.lower()
        assert os.path.isfile(result.raw_log_reference)


class TestSuccessfulTool:
    def test_stdout_parsed(self, tmp_path):
        payload = "sub1.example.com\nsub2.example.com\n"
        if os.name == "nt":
            argv = ["-c", "print(open(r'%s').read(), end='')" % _write_input(tmp_path, payload)]
        else:
            argv = ["-c", f"print(open('{_write_input(tmp_path, payload)}').read(), end='')"]
        spec = make_spec(
            sys.executable, argv, name="subfinder", parser_name="subfinder"
        )
        cfg = make_config(tmp_path)
        runner = ToolRunner(spec, cfg, str(tmp_path / "logs"))
        result = asyncio.run(runner.run({"files": {}}))

        assert result.status == "success"
        assert result.retries_used == 1
        subs = [f["subdomain"] for f in result.findings]
        assert subs == ["sub1.example.com", "sub2.example.com"]
        assert os.path.isfile(result.raw_log_reference)


def _write_input(tmp_path, text: str) -> str:
    path = tmp_path / "_input.txt"
    write_text_file(str(path), text)
    return str(path)


class TestTimeout:
    def test_timeout_kills_and_marks_failed(self, tmp_path):
        # Sleeps forever; must be killed by the timeout enforcement.
        code = "import time; time.sleep(600)"
        spec = make_spec(sys.executable, ["-c", code])
        cfg = make_config(tmp_path, tool_timeout_sec=1, max_retries=2)
        runner = ToolRunner(spec, cfg, str(tmp_path / "logs"))
        result = asyncio.run(runner.run({"files": {}}))

        assert result.status == "failed"
        assert result.retries_used == 2
        assert "timeout" in result.error_summary.lower()
        assert os.path.isfile(result.raw_log_reference)
