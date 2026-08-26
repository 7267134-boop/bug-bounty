"""Stage 2 toolchain tests: parsers, registry, stdin execution."""

import asyncio
import sys
from pathlib import Path

import pytest

from master.orchestrator import load_workflow

from worker.executor import Executor
from worker.tools.base import ExecResult, ToolContext, ToolNotPermitted
from worker.tools.registry import known_tools, resolve_tool
import worker.tools.registry  # noqa: F401


def _ctx(tmp_path, target="example.com", params=None, inputs=None,
         input_file=None) -> ToolContext:
    return ToolContext(
        task_id="t1", scan_id="s1", program_id="p1", step_name="step",
        target=target, params=params or {}, attempt=1, timeout_secs=30,
        max_output_bytes=100_000, workdir=str(tmp_path),
        inputs=inputs or {}, input_file=input_file,
    )


def _res(stdout: str) -> ExecResult:
    return ExecResult(0, stdout, "", 10)


class TestRegistry:
    def test_all_stage2_tools_registered(self):
        for name in ("subfinder", "assetfinder", "amass", "dnsx", "httpx",
                     "naabu", "waybackurls", "katana", "nuclei", "uncover"):
            assert name in known_tools(), name

    def test_capability_gate_still_enforced(self):
        with pytest.raises(ToolNotPermitted):
            resolve_tool("nuclei", ["subfinder"])

class TestEnumParsers:
    def test_subfinder_jsonl(self, tmp_path):
        tool = resolve_tool("subfinder", ["subfinder"])
        out = ('{"host":"api.example.com","source":"crtsh"}\n'
               'noise\n{"host":"api.example.com"}\n')
        findings = tool.parse(_res(out), _ctx(tmp_path))
        subs = [f["subdomain"] for f in findings]
        assert subs == ["api.example.com"]

    def test_subfinder_rejects_unknown_params(self, tmp_path):
        tool = resolve_tool("subfinder", ["subfinder"])
        from worker.tools.base import ToolExecutionError

        with pytest.raises(ToolExecutionError):
            tool.build_argv(_ctx(tmp_path, params={"evil": "; rm -rf /"}))

    def test_assetfinder_lines(self, tmp_path):
        tool = resolve_tool("assetfinder", ["assetfinder"])
        out = "dev.example.com\nExample.COM.\n\n-\n"
        findings = tool.parse(_res(out), _ctx(tmp_path))
        assert [f["subdomain"] for f in findings] == ["dev.example.com", "example.com"]

    def test_amass_filters_out_of_namespace(self, tmp_path):
        tool = resolve_tool("amass", ["amass"])
        out = ("sub.example.com\nunrelated-other.net\n[cores] noise line\n"
               "www.example.com\n")
        findings = tool.parse(_res(out), _ctx(tmp_path))
        subs = {f["subdomain"] for f in findings}
        assert subs == {"sub.example.com", "www.example.com"}

class TestProbeParsers:
    def test_dnsx_resp(self, tmp_path):
        tool = resolve_tool("dnsx", ["dnsx"])
        rec = '{"host":"a.example.com","a":["1.2.3.4","1.2.3.5"]}'
        findings = tool.parse(_res(rec + "\nbad\n"), _ctx(tmp_path))
        ips = sorted(f["value"] for f in findings)
        assert ips == ["1.2.3.4", "1.2.3.5"]
        assert all(f["hostname"] == "a.example.com" for f in findings)

    def test_httpx_live_hosts(self, tmp_path):
        tool = resolve_tool("httpx", ["httpx"])
        out = ('{"url":"https://a.example.com","status_code":200,"title":"A",'
               '"tech":["Nginx"],"webserver":"nginx"}\n'
               '{"input":"https://b.example.com","status_code":403}\n')
        findings = tool.parse(_res(out), _ctx(tmp_path))
        live = [f for f in findings if f["type"] == "live_host"]
        assert len(live) == 2
        first = live[0]
        assert first["title"] == "A"
        assert live[1]["technologies"] == []
        # R4 signal: the 403 response also emits a routing finding
        assert any(f["type"] == "http_403" and f["value"] == "https://b.example.com"
                   for f in findings)

    def test_naabu_ports(self, tmp_path):
        tool = resolve_tool("naabu", ["naabu"])
        out = ('{"host":"a.example.com","ip":"1.2.3.4","port":443}\n'
               '{"host":"a.example.com","port":80}\njunk\n')
        findings = tool.parse(_res(out), _ctx(tmp_path))
        values = sorted(f["value"] for f in findings)
        assert values == ["a.example.com:443", "a.example.com:80"]

class TestVulnParsers:
    def test_waybackurls_param_split(self, tmp_path):
        tool = resolve_tool("waybackurls", ["waybackurls"])
        out = "https://x.com/a\nhttps://x.com/p?q=1\n\nhas space\n"
        findings = tool.parse(_res(out), _ctx(tmp_path))
        types = sorted(f["type"] for f in findings)
        assert types == ["archive_url", "archive_url", "url_param"]
        assert findings[-1]["url"] == "https://x.com/p?q=1"

    def test_waybackurls_stdin_payload(self, tmp_path):
        tool = resolve_tool("waybackurls", ["waybackurls"])
        ctx = _ctx(tmp_path, inputs={"subdomain": ["a.com", "b.com", "a.com"]})
        assert tool.stdin_data(ctx) == b"a.com\nb.com\n"

    def test_katana_nested_endpoint(self, tmp_path):
        tool = resolve_tool("katana", ["katana"])
        out = ('{"request":{"endpoint":"https://x.com/page"},"response":{}}\n'
               '{"request":{"endpoint":"https://x.com/s?q=2"}}\n')
        findings = tool.parse(_res(out), _ctx(tmp_path))
        types = sorted(f["type"] for f in findings)
        assert types == ["url", "url", "url_param"]

    def test_nuclei_severity_and_composite_value(self, tmp_path):
        tool = resolve_tool("nuclei", ["nuclei"])
        rec = ('{"template-id":"CVE-2024-1","info":{"name":"X","severity":"HIGH",'
               '"classification":{"cve-id":["CVE-2024-1"],"cvss-score":9.8}},'
               '"matched-at":"https://x.com/"}\n')
        findings = tool.parse(_res(rec), _ctx(tmp_path))
        v = findings[0]
        assert v["severity"] == "high"
        assert v["value"] == "CVE-2024-1@https://x.com/"
        assert v["cve_ids"] == ["CVE-2024-1"]

    def test_uncover_blocks_foreign_hosts(self, tmp_path):
        tool = resolve_tool("uncover", ["uncover"])
        out = ('{"host":"sub.example.com","ip":"1.1.1.1","port":443}\n'
               '{"host":"evil.other.net","port":22}\n'
               '{"ip":"2.2.2.2","port":80}\n')
        findings = tool.parse(_res(out), _ctx(tmp_path))
        values = {f.get("value") for f in findings}
        assert "sub.example.com:443" in values
        assert all(v is None or "other.net" not in str(v) for v in values)


class TestExecutorStdin:
    def test_stdin_data_reaches_process(self, tmp_path):
        async def run():
            ex = Executor()
            return ex.run(
                [sys.executable, "-c",
                 "import sys; print(sys.stdin.read().strip().upper())"],
                _ctx(tmp_path), stdin_bytes=b"hello-pipeline\n",
            )

        result = asyncio.run(run())
        assert result.ok and "HELLO-PIPELINE" in result.stdout


class TestReconWorkflow:
    def test_recon_yaml_valid_with_deps(self):
        path = Path(__file__).resolve().parent.parent / "workflows" / "recon.yaml"
        wf = load_workflow(path)
        names = {s["name"] for s in wf["steps"]}
        assert {"subdomain_subfinder", "probe_web", "vulnerability_scan"} <= names
        probe = next(s for s in wf["steps"] if s["name"] == "probe_web")
        # R1: probe is gated on the DNS filter (massdns), not the raw enum steps
        assert probe["depends_on"] == ["resolve_dns"]



