"""Unit tests for tool output parsers (Strategy Pattern implementations)."""

from recon.parsers import (
    HttpxParser,
    LineParser,
    NaabuParser,
    NmapParser,
    NucleiParser,
    SubfinderParser,
    parse_findings,
)


class TestSubfinder:
    def test_parses_lines_and_dedupes(self):
        out = "api.example.com\nwww.example.com\napi.example.com\n\n"
        findings = SubfinderParser().parse(out, "", "example.com")
        values = [f["subdomain"] for f in findings]
        assert values == ["api.example.com", "www.example.com"]
        assert all(f["type"] == "subdomain" for f in findings)


class TestNaabu:
    def test_host_port_pairs(self):
        out = "1.2.3.4:80\n1.2.3.4:443\nbadline\n1.2.3.4:80\n"
        findings = NaabuParser().parse(out, "", "example.com")
        assert {"host": "1.2.3.4", "port": 80} in [
            {"host": f["host"], "port": f["port"]} for f in findings
        ]
        assert len(findings) == 2


class TestHttpx:
    def test_json_lines(self):
        out = (
            '{"url":"https://api.example.com","status_code":200,"title":"API",'
            '"tech":["nginx"],"webserver":"nginx"}\n'
            'not-json-noise\n'
            '{"input":"https://old.example.com","status_code":301}\n'
        )
        findings = HttpxParser().parse(out, "", "example.com")
        assert len(findings) == 2
        first = findings[0]
        assert first["type"] == "live_host"
        assert first["status_code"] == 200
        assert first["title"] == "API"
        assert first["technologies"] == ["nginx"]


class TestNuclei:
    def test_vulnerability_findings(self):
        record = (
            '{"template-id":"CVE-2021-44228","info":{"name":"Apache Log4j RCE",'
            '"severity":"critical","tags":["cve","rce"],"description":"Log4Shell",'
            '"classification":{"cve-id":["CVE-2021-44228"],"cvss-score":10.0},'
            '"reference":["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]},'
            '"matched-at":"https://api.example.com/x","matcher-status":true}\n'
        )
        findings = NucleiParser().parse(record, "", "example.com")
        assert len(findings) == 1
        v = findings[0]
        assert v["type"] == "vulnerability"
        assert v["severity"] == "critical"
        assert v["id"] == "CVE-2021-44228"
        assert v["cve_ids"] == ["CVE-2021-44228"]
        assert v["matched_at"] == "https://api.example.com/x"

    def test_unknown_severity_normalized(self):
        rec = '{"template-id":"x","info":{"name":"X","severity":"weird"},"matched-at":"/"}'
        (v,) = NucleiParser().parse(rec, "", "t.com")
        assert v["severity"] == "unknown"


class TestNmap:
    def test_greppable_output(self):
        out = (
            "# Nmap 7.94 scan initiated\n"
            "Host: 93.184.216.34 (example.com)\tStatus: Up\n"
            "Host: 93.184.216.34 (example.com)\tPorts: 80/open/tcp//http//nginx/, "
            "443/open/tcp//https//nginx/, 22/closed/tcp//ssh///\tIgnored State: closed\n"
            "# Nmap done\n"
        )
        findings = NmapParser().parse(out, "", "example.com")
        assert len(findings) == 1
        host = findings[0]
        assert host["type"] == "host_ports"
        assert host["hostname"] == "example.com"
        ports = {p["port"]: p for p in host["ports"]}
        assert set(ports) == {80, 443}
        assert ports[80]["service"] == "http"
        assert "nginx" in ports[80]["version"]


class TestRegistry:
    def test_parse_findings_dispatches_by_tool(self):
        out = "a.example.com\n"
        findings = parse_findings("subfinder", out, "", "example.com")
        assert findings and findings[0]["subdomain"] == "a.example.com"

    def test_unknown_tool_falls_back_to_lines(self):
        findings = parse_findings("mysterytool", "line1\n", "", "t.com")
        assert findings[0]["value"] == "line1"

    def test_parser_never_crashes_pipeline(self):
        assert parse_findings("subfinder", object(), object(), "t.com") == []

    def test_base_line_parser(self):
        findings = LineParser().parse("x\ny\n", "", "t.com")
        assert [f["value"] for f in findings] == ["x", "y"]
