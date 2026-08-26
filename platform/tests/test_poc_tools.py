"""PoC tests for the Stage-4 wrapper pair: dalfox + gowitness."""

import os

import pytest

from master.orchestrator import ALLOWED_TOOLS

from worker.tools.base import ExecResult, ToolExecutionError
from worker.tools.registry import known_tools, resolve_tool

from _helpers import _ctx


class TestDalfox:
    def test_registered_and_allowed_by_master(self):
        assert "dalfox" in known_tools()
        assert "dalfox" in ALLOWED_TOOLS

    def test_data_contract(self):
        tool = resolve_tool("dalfox", ["dalfox"])
        assert tool.consumes == ["url_param"]
        assert tool.produces == ["vulnerability"]
        assert tool.needs_input_file is True

    def test_build_argv_uses_file_mode_without_shell_chars(self, tmp_path):
        tool = resolve_tool("dalfox", ["dalfox"])
        ctx = _ctx(tmp_path, params={"workers": 20},
                   input_file=str(tmp_path / "input.txt"))
        argv = tool.build_argv(ctx)
        joined = " ".join(argv)
        assert argv[0] == "dalfox" and "file" in argv
        assert str(tmp_path / "input.txt") in argv
        for banned in ("|", ">", ";", "`", "$(", "&&"):
            assert banned not in joined, f"shell char {banned!r} leaked into argv"

    def test_unknown_param_rejected(self, tmp_path):
        tool = resolve_tool("dalfox", ["dalfox"])
        with pytest.raises(ToolExecutionError):
            tool.build_argv(_ctx(tmp_path, params={"raw_cmd": "-X payload"}))

    def test_parse_vuln_events_only(self, tmp_path):
        tool = resolve_tool("dalfox", ["dalfox"])
        stdout = (
            '{"type":"V","url":"https://x.com/s?q=1","data":{"injected":"<svg>",'
            '"payload":"\\"><svg>","message":"PoC","type":"reflected"}}\n'
            '{"type":"R","url":"https://x.com/s?q=1","data":{"message":"reflected hint"}}\n'
            '{"type":"I","data":{"message":"info only"}}\n'
            'garbage line\n'
        )
        findings = tool.parse(_res := ExecResult(0, stdout, "", 5), _ctx(tmp_path))
        assert len(findings) == 1
        v = findings[0]
        assert v["id"] == "dalfox-xss"
        assert v["value"] == "dalfox-xss@https://x.com/s?q=1"
        assert v["severity"] == "medium"
        assert v["tags"] == ["xss", "dalfox"]
        assert v["evidence"]["injected"] == "<svg>"

    def test_duplicate_urls_deduped(self, tmp_path):
        tool = resolve_tool("dalfox", ["dalfox"])
        evt = ('{"type":"V","url":"https://x.com/a?b=2",'
               '"data":{"injected":"p"}}\n')
        findings = tool.parse(ExecResult(0, evt * 2, "", 5), _ctx(tmp_path))
        assert len(findings) == 1


class TestGowitness:
    def test_registered_and_allowed_by_master(self):
        assert "gowitness" in known_tools()
        assert "gowitness" in ALLOWED_TOOLS

    def test_data_contract(self):
        tool = resolve_tool("gowitness", ["gowitness"])
        assert tool.consumes == ["live_host"]
        assert tool.produces == ["screenshot"]
        assert tool.needs_input_file is True

    def test_build_argv_targets_workdir_screenshot_dir(self, tmp_path):
        tool = resolve_tool("gowitness", ["gowitness"])
        ctx = _ctx(tmp_path, input_file=str(tmp_path / "in.txt"))
        argv = tool.build_argv(ctx)
        joined = " ".join(argv)
        assert argv[0] == "gowitness" and "scan" in argv and "file" in argv
        assert str(tmp_path / "in.txt") in argv
        expected_dir = str(tmp_path / "screenshots")
        assert expected_dir in joined
        for banned in ("|", ">", ";", "`", "&&"):
            assert banned not in joined

    def test_parse_lists_png_artifacts(self, tmp_path):
        tool = resolve_tool("gowitness", ["gowitness"])
        ctx = _ctx(tmp_path)
        shots = tmp_path / "screenshots"
        shots.mkdir()
        for name in ("a.example.com.png", "b.example.com_8443.jpg",
                     "notes.txt"):
            (shots / name).write_bytes(b"\x89PNG fake")
        findings = tool.parse(_res := ExecResult(0, "", "", 1), ctx)
        values = [f["value"] for f in findings]
        # NOTE: real gowitness names may contain ':' (host:port); on NTFS the
        # test uses '_' since ':' is reserved there.
        assert values == ["a.example.com", "b.example.com_8443"]
        assert all(f["type"] == "screenshot" for f in findings)
        assert all(os.path.isfile(f["artifact"]) for f in findings)

    def test_parse_without_screenshot_dir_is_empty(self, tmp_path):
        tool = resolve_tool("gowitness", ["gowitness"])
        assert tool.parse(_res := ExecResult(0, "", "", 1), _ctx(tmp_path)) == []
