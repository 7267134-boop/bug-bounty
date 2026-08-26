"""Stage 3 decision-engine tests: signals, routed wrappers, chain gates."""

import json
import sys
from pathlib import Path

import pytest

from master.orchestrator import ALLOWED_TOOLS, load_workflow

from worker.tools.base import ExecResult
from worker.tools.registry import known_tools, resolve_tool

from _helpers import _ctx, _res

WORKFLOWS = Path(__file__).resolve().parent.parent / "workflows"

class TestHttpxSignals:
    def test_403_and_api_and_login_signals(self, tmp_path):
        tool = resolve_tool("httpx", ["httpx"])
        out = (
            '{"url":"https://x.com/admin","status_code":403}\n'
            '{"url":"https://x.com/api/v1/users","status_code":200,"tech":["nginx"]}\n'
            '{"url":"https://x.com/login","status_code":200,"title":"Sign in"}\n'
            '{"url":"https://wp.example.com","status_code":200,'
            '"title":"Just another WordPress site","tech":["WordPress"]}\n'
        )
        findings = tool.parse(_res(out), _ctx(tmp_path))
        by_type: dict[str, list] = {}
        for f in findings:
            by_type.setdefault(f["type"], []).append(f["value"])
        assert by_type.get("http_403") == ["https://x.com/admin"]
        assert by_type.get("api_surface") == ["https://x.com/api/v1/users"]
        assert by_type.get("login_page") == ["https://x.com/login"]
        assert by_type.get("wordpress") == ["https://wp.example.com"]
        assert len(by_type["live_host"]) == 4      # base entity always present

    def test_produces_declares_signals(self):
        tool = resolve_tool("httpx", ["httpx"])
        for sig in ("wordpress", "http_403", "login_page", "api_surface"):
            assert sig in tool.produces


class TestNmapExposedServiceSignal:
    def test_risky_port_emits_exposed_service(self, tmp_path):
        tool = resolve_tool("nmap", ["nmap"])
        out = (
            "Host: 1.2.3.4 ()\tPorts: 3306/open/tcp//mysql//MySQL 8/, "
            "443/open/tcp//https//nginx/\tSeq\n"
        )
        findings = tool.parse(_res(out), _ctx(tmp_path))
        exposed = [f for f in findings if f["type"] == "exposed_service"]
        assert len(exposed) == 1
        assert exposed[0]["port"] == 3306
        assert any(f["type"] == "service" and f["port"] == 443 for f in findings)

class TestBypass403:
    def test_registered_and_allowed(self):
        assert "routing.bypass403" in known_tools()
        assert "routing.bypass403" in ALLOWED_TOOLS

    def test_contract(self, tmp_path):
        tool = resolve_tool("routing.bypass403", ["routing.bypass403"])
        assert tool.consumes == ["http_403"]
        assert tool.produces == ["vulnerability"]
        ctx = _ctx(tmp_path, input_file=str(tmp_path / "in.txt"))
        argv = tool.build_argv(ctx)
        assert argv[0] == sys.executable and "-c" in argv
        assert str(tmp_path / "in.txt") in argv      # script reads the file

    def test_parse_hits_only(self, tmp_path):
        tool = resolve_tool("routing.bypass403", ["routing.bypass403"])
        out = (
            '{"url":"https://x.com/admin","technique":"x-original-url",'
            '"status":200,"tested_url":"https://x.com/admin"}\n'
            '{"url":"https://y.com/admin","technique":"dot-slash",'
            '"status":500,"tested_url":"https://y.com/admin/."}\n'
            'not-json\n'
        )
        findings = tool.parse(_res(out), _ctx(tmp_path))
        assert len(findings) == 1                    # 500 is not a bypass
        f = findings[0]
        assert f["id"] == "bypass403"
        assert f["value"] == "bypass403:x-original-url@https://x.com/admin"
        assert f["evidence"]["status"] == 200


class TestWpscan:
    def test_batch_builds_one_argv_per_url_with_unique_outfiles(self, tmp_path):
        tool = resolve_tool("wpscan", ["wpscan"])
        ctx = _ctx(tmp_path,
                   inputs={"wordpress": ["https://a.com", "https://b.com"]},
                   input_file=str(tmp_path / "in.txt"))
        batch = tool.build_argv_batch(ctx)
        assert len(batch) == 2
        outs = [argv[argv.index("-o") + 1] for argv in batch]
        assert len(set(outs)) == 2                   # unique output files
        for argv, url in zip(batch, ["https://a.com", "https://b.com"]):
            assert "--url" in argv and url in argv
            assert "--format" in argv and "json" in argv

    def test_parse_wpscan_json(self, tmp_path):
        tool = resolve_tool("wpscan", ["wpscan"])
        doc = {
            "target_url": "https://wp.example.com",
            "plugins": {
                "contact-form-7": {
                    "slug": "contact-form-7",
                    "vulnerabilities": [{
                        "title": "CF7 Unrestricted Upload",
                        "severity": "high",
                        "fixed_in": "5.3.9",
                        "cvss": {"score": 8.8},
                        "references": {"url": ["https://ref/x"]},
                    }],
                }
            },
        }
        (tmp_path / "wpscan_0.json").write_text(json.dumps(doc),
                                                encoding="utf-8")
        findings = tool.parse(
            ExecResult(0, "", "", 1), _ctx(tmp_path))
        assert len(findings) == 1
        v = findings[0]
        assert v["id"] == "wpscan-contact-form-7"
        assert v["severity"] == "high"
        assert v["cvss_score"] == 8.8
        assert v["evidence"]["fixed_in"] == "5.3.9"

class TestCorsy:
    def test_registered_and_contract(self):
        assert "corsy" in known_tools()
        tool = resolve_tool("corsy", ["corsy"])
        assert tool.consumes == ["api_surface"]
        assert tool.produces == ["cors_misconfig"]

    def test_parse_cors_lines(self, tmp_path):
        tool = resolve_tool("corsy", ["corsy"])
        out = (
            "[+] CORS Misconfiguration: https://api.x.com (origin reflection)\n"
            "short\n"
            "[+] CORS Misconfiguration: https://api2.x.com (null origin)\n"
        )
        findings = tool.parse(_res(out), _ctx(tmp_path))
        values = [f["value"] for f in findings]
        assert len(values) == 2
        assert all(f["type"] == "cors_misconfig" for f in findings)


class TestDeepReconChain:
    @pytest.fixture(scope="class")
    @classmethod
    def wf(cls):
        return load_workflow(WORKFLOWS / "deep-recon.yaml")

    def test_all_routed_steps_present(self, wf):
        names = {s["name"] for s in wf["steps"]}
        assert {"bypass403_check", "wpscan_sites", "cors_scan",
                "service_enum", "xss_scan"} <= names

    def test_gates_key_off_signals(self, wf):
        gates = {s["name"]: s.get("when", {}).get("has_finding_type")
                 for s in wf["steps"]}
        assert gates["bypass403_check"] == "http_403"
        assert gates["wpscan_sites"] == "wordpress"
        assert gates["cors_scan"] == "api_surface"

    def test_tools_allowed_on_master(self, wf):
        for s in wf["steps"]:
            assert s["tool"] in ALLOWED_TOOLS



