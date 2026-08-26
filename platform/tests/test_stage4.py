"""Stage 4 focused-scanning tests: ffuf/arjun/sqlmap/trufflehog wrappers."""

import json
import sys
from pathlib import Path

import pytest

from master.orchestrator import ALLOWED_TOOLS, load_workflow

from worker.tools.base import ExecResult, ToolExecutionError
from worker.tools.registry import known_tools, resolve_tool

from _helpers import _ctx, _res

WORKFLOWS = Path(__file__).resolve().parent.parent / "workflows"

class TestFfuf:
    def test_registered_and_allowed(self):
        assert "ffuf" in known_tools() and "ffuf" in ALLOWED_TOOLS

    def test_batch_per_host_with_fallback_wordlist(self, tmp_path, monkeypatch):
        tool = resolve_tool("ffuf", ["ffuf"])
        ctx = _ctx(tmp_path,
                   inputs={"live_host": ["https://a.com", "https://b.com"]})
        batch = tool.build_argv_batch(ctx)
        assert len(batch) == 2
        for argv in batch:
            joined = " ".join(argv)
            assert "-w" in argv and "-u" in argv and "FUZZ" in joined
            assert "wordlist_common.txt:FUZZ" in joined   # bundled fallback

    def test_explicit_wordlist_wins(self, tmp_path):
        custom = tmp_path / "custom.txt"
        custom.write_text("admin\n")
        tool = resolve_tool("ffuf", ["ffuf"])
        ctx = _ctx(tmp_path, params={"wordlist": str(custom)},
                   inputs={"live_host": ["https://a.com"]})
        argv = tool.build_argv_batch(ctx)[0]
        assert any(a.startswith(str(custom) + ":FUZZ") for a in argv)

    def test_missing_wordlist_everywhere_raises(self, tmp_path, monkeypatch):
        import worker.tools.focused_scan as fs_mod

        monkeypatch.setattr(fs_mod, "FALLBACK_WORDLIST", "/nope/fallback.txt")
        tool = resolve_tool("ffuf", ["ffuf"])
        ctx = _ctx(tmp_path, params={"wordlist": "/nope/none.txt"},
                   inputs={"live_host": ["https://a.com"]})
        with pytest.raises(ToolExecutionError):
            tool.build_argv_batch(ctx)

    def test_parse_ffuf_json(self, tmp_path):
        tool = resolve_tool("ffuf", ["ffuf"])
        doc = {"results": [{"url": "https://a.com/admin",
                            "status": 200, "length": 1200, "words": 90}]}
        (tmp_path / "ffuf_0.json").write_text(json.dumps(doc))
        findings = tool.parse(_res(""), _ctx(tmp_path))
        f = findings[0]
        assert f["type"] == "discovered_url"
        assert f["status_code"] == 200


def wordlist_used(argv: list[str]) -> str:
    return argv[argv.index("-w") + 1]

class TestArjun:
    def test_registered_and_contract(self):
        assert "arjun" in known_tools() and "arjun" in ALLOWED_TOOLS
        tool = resolve_tool("arjun", ["arjun"])
        assert tool.consumes == ["live_host", "api_surface"]
        assert tool.produces == ["url_param"]

    def test_parse_outjson_to_url_params(self, tmp_path):
        tool = resolve_tool("arjun", ["arjun"])
        (tmp_path / "arjun.json").write_text(json.dumps({
            "https://x.com/api/users": {"id": ["1"], "debug": ["true"]},
        }), encoding="utf-8")
        ctx = _ctx(tmp_path, input_file=str(tmp_path / "in.txt"))
        findings = tool.parse(_res(""), ctx)
        values = {f["value"] for f in findings}
        assert "https://x.com/api/users?id=<fuzz>" in values
        assert all(f["type"] == "url_param" for f in findings)


class TestSqlmap:
    def test_conservative_defaults(self, tmp_path):
        tool = resolve_tool("sqlmap", ["sqlmap"])
        ctx = _ctx(tmp_path, inputs={"url_param":
                                     ["https://x.com/a?id=1"]},
                   input_file=str(tmp_path / "in.txt"))
        argvs = tool.build_argv_batch(ctx)
        argv = argvs[0]
        assert "--batch" in argv and "--level=1".replace("=", "") not in argv
        assert "--level" in argv and "1" in argv
        assert "--risk" in argv and "1" in argv
        assert len(argvs) == 1                          # cap respected

    def test_max_urls_cap(self, tmp_path):
        tool = resolve_tool("sqlmap", ["sqlmap"])
        ctx = _ctx(tmp_path, inputs={"url_param":
                                     [f"https://x.com/?id={i}"
                                      for i in range(25)]})
        batch = tool.build_argv_batch(ctx)
        assert len(batch) == 10                         # hard cap

    def test_parse_vulnerable_blocks(self, tmp_path):
        tool = resolve_tool("sqlmap", ["sqlmap"])
        stdout = (
            "[INFO] testing 'AND boolean'\n"
            "GET parameter 'id' is vulnerable. Do you want... \n"
            "Parameter: id (GET)\n"
            "    Type: boolean-based blind\n"
            "---\n"
            "GET parameter 'q' is vulnerable.\n"
            "Parameter: q (GET)\n"
            "    Type: union query\n"
        )
        findings = tool.parse(_res(stdout), _ctx(tmp_path))
        params = sorted(f["evidence"]["parameter"] for f in findings)
        assert params == ["id", "q"]
        assert all(f["severity"] == "high"
                   and f["id"] == "sqlmap-sqli" for f in findings)


class TestTrufflehog:
    def test_registered_and_redaction(self, tmp_path):
        tool = resolve_tool("trufflehog", ["trufflehog"])
        assert tool.consumes == ["js_url"]
        secret_line = json.dumps({
            "SourceMetadata": {"Data": {"Filesystem": {
                "file": "/tmp/js/app.js"}}},
            "DetectorName": "AWS",
            "Raw": "AKIAIOSFODNN7EXAMPLESECRET",
            "Verified": True,
        })
        findings = tool.parse(_res(secret_line), _ctx(tmp_path))
        (f,) = findings
        assert f["detector"] == "AWS" and f["severity"] == "critical"
        assert f["redacted_preview"] == "AKIAIOSFODNN"
        # the full secret must NOT leak into any stored field
        dumped = json.dumps(f)
        assert "AKIAIOSFODNN7EXAMPLESECRET" not in dumped

    def test_build_argv_driver_includes_caps(self, tmp_path):
        tool = resolve_tool("trufflehog", ["trufflehog"])
        ctx = _ctx(tmp_path, input_file=str(tmp_path / "urls.txt"),
                   params={"max_files": 5})
        argv = tool.build_argv(ctx)
        assert argv[0] == sys.executable and "-c" in argv
        driver = argv[2]
        assert "MAX_FILES=5" in driver
        assert "trufflehog" in driver and "filesystem" in driver


class TestFocusedWorkflow:
    @pytest.fixture(scope="class")
    @classmethod
    def wf(cls):
        return load_workflow(WORKFLOWS / "focused.yaml")

    def test_stage4_gates(self, wf):
        gates = {s["name"]: s.get("when", {}).get("has_finding_type")
                 for s in wf["steps"]}
        assert gates["content_discovery"] == "live_host"
        assert gates["param_mining"] == "api_surface"
        assert gates["sqli_validation"] == "url_param"
        assert gates["js_secrets"] == "js_url"

    def test_sqlmap_runs_after_param_mining(self, wf):
        sqli = next(s for s in wf["steps"] if s["name"] == "sqli_validation")
        assert "param_mining" in sqli["depends_on"]

    def test_all_tools_allowed_on_master(self, wf):
        for s in wf["steps"]:
            assert s["tool"] in ALLOWED_TOOLS


