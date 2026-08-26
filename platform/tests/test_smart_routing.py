"""Smart-routing tests: massdns/nmap wrappers, producer signals, chain."""

from pathlib import Path

import pytest

from master.orchestrator import load_workflow

from worker.tools.base import ExecResult, ToolExecutionError
from worker.tools.registry import known_tools, resolve_tool, get_tool

from _helpers import _ctx, _res

WORKFLOWS = Path(__file__).resolve().parent.parent / "workflows"


class TestMassdns:
    def test_registered(self):
        assert "massdns" in known_tools()

    def test_contract_and_argv(self, tmp_path):
        tool = resolve_tool("massdns", ["massdns"])
        assert (tool.consumes, tool.produces) == (["subdomain"],
                                                  ["resolved_host"])
        ctx = _ctx(tmp_path, input_file=str(tmp_path / "in.txt"))
        argv = tool.build_argv(ctx)
        assert "massdns" in argv and "-r" in argv          # resolver list wired
        assert str(tmp_path / "in.txt") in argv            # positional list input
        assert "-o" in argv and "S" in argv                # parseable output
        assert not any(c in " ".join(argv) for c in "|>;&`")

    def test_parse_drops_dead_and_dedupes(self, tmp_path):
        tool = resolve_tool("massdns", ["massdns"])
        out = ("alive.example.com\nalive.example.com\n"
               "# comment\n;comment\nno-dots\nALIVE2.EXAMPLE.COM.\n")
        findings = tool.parse(_res(out), _ctx(tmp_path))
        values = [f["value"] for f in findings]
        assert values == ["alive.example.com", "alive2.example.com"]
        assert all(f["type"] == "resolved_host" for f in findings)

class TestNmapTargeted:
    def test_registered(self):
        assert "nmap" in known_tools()

    def test_argv_scoped_to_discovered_ports_only(self, tmp_path):
        tool = resolve_tool("nmap", ["nmap"])
        ctx = _ctx(tmp_path, input_file=str(tmp_path / "ports.txt"),
                   inputs={"open_port": ["a.example.com:443",
                                         "b.example.com:8080",
                                         "a.example.com:22"]})
        argv = tool.build_argv(ctx)
        assert "-sV" in argv and "-sC" in argv and "--open" in argv
        port_flag = argv[argv.index("-p") + 1]
        assert sorted(port_flag.split(",")) == ["22", "443", "8080"]  # union only
        assert "-iL" in argv                       # hosts restricted too
        joined = " ".join(argv)
        for banned in ("|", ">", ";", "`"):
            assert banned not in joined

    def test_empty_ports_raises_non_retryable(self, tmp_path):
        tool = resolve_tool("nmap", ["nmap"])
        ctx = _ctx(tmp_path, inputs={"open_port": []},
                   input_file=str(tmp_path / "empty.txt"))
        with pytest.raises(ToolExecutionError):
            tool.build_argv(ctx)

    def test_parse_greppable_services(self, tmp_path):
        tool = resolve_tool("nmap", ["nmap"])
        out = (
            "# Nmap scan\n"
            "Host: 1.2.3.4 (a.example.com)\tStatus: Up\n"
            "Host: 1.2.3.4 (a.example.com)\tPorts: "
            "443/open/tcp//https//nginx/, 8080/open/tcp//http-proxy//squid/, "
            "21/closed/tcp//ftp///\tSeq\n"
        )
        findings = tool.parse(_res(out), _ctx(tmp_path))
        got = {(f["host"], f["port"], f["service"]) for f in findings}
        assert ("1.2.3.4", 443, "https") in got
        assert ("1.2.3.4", 8080, "http-proxy") in got
        assert all(f["type"] == "service" for f in findings)

class TestProducerSignals:
    """httpx/katana must emit the routing signals the gates consume."""

    def test_httpx_emits_wordpress_signal(self, tmp_path):
        tool = resolve_tool("httpx", ["httpx"])
        out = ('{"url":"https://wp.example.com","status_code":200,'
               '"title":"Just another WordPress site","tech":["WordPress"]}\n'
               '{"url":"https://plain.example.com","status_code":200,'
               '"tech":["nginx"]}\n')
        findings = tool.parse(_res(out), _ctx(tmp_path))
        wp = [f["value"] for f in findings if f["type"] == "wordpress"]
        assert wp == ["https://wp.example.com"]

    def test_katana_emits_js_urls(self, tmp_path):
        tool = resolve_tool("katana", ["katana"])
        out = ('{"request":{"endpoint":"https://x.com/app.js"}}\n'
               '{"request":{"endpoint":"https://x.com/page"}}\n')
        findings = tool.parse(_res(out), _ctx(tmp_path))
        js = [f["value"] for f in findings if f["type"] == "js_url"]
        assert js == ["https://x.com/app.js"]


class TestReconChain:
    @pytest.fixture(scope="class")
    @classmethod
    def wf(cls):
        return load_workflow(WORKFLOWS / "recon.yaml")

    def test_dns_filter_is_massdns(self, wf):
        resolve_step = next(s for s in wf["steps"]
                            if s["name"] == "resolve_dns")
        assert resolve_step["tool"] == "massdns"

    def test_probe_depends_on_dns_filter(self, wf):
        probe = next(s for s in wf["steps"] if s["name"] == "probe_web")
        assert "resolve_dns" in probe["depends_on"]

    def test_nmap_gated_on_open_ports(self, wf):
        nmap = next(s for s in wf["steps"] if s["name"] == "service_enum")
        assert nmap["tool"] == "nmap"
        assert nmap["when"]["has_finding_type"] == "open_port"

    def test_dalfox_gated_on_params(self, wf):
        dalfox = next(s for s in wf["steps"] if s["name"] == "xss_scan")
        assert dalfox["when"]["has_finding_type"] == "url_param"

    def test_wrapper_contracts_match_chain(self):
        httpx_t = get_tool("httpx")
        naabu_t = get_tool("naabu")
        massdns_t = get_tool("massdns")
        # R1: probers/scanners consume the FILTERED type only
        assert httpx_t.consumes == ["resolved_host"]
        assert "resolved_host" in naabu_t.consumes
        assert "subdomain" not in naabu_t.consumes
        # and the filter itself is produced by massdns
        assert "resolved_host" in massdns_t.produces


