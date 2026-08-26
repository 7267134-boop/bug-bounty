"""Parser/config/notification edge cases and failure modes."""

import asyncio

import pytest

from common.config import load_settings
from common.testing import make_test_settings
from worker.tools.registry import resolve_tool

from _helpers import _ctx, _res


class TestMalformedInputs:
    """Tools must tolerate garbage output without crashing the pipeline."""

    CASES = {
        "subfinder": "{{{not json\n[]\n{\"nonsense\":true}\n",
        "assetfinder": "///\n---\n\x00binary-ish\n",
        "amass": "[WARN] whatever\n\n\t\nno dots here\n",
        "dnsx": "{truncated\n{\"host\":\"\"}\n",
        "httpx": "{half json\n{\"url\":\"\"}\n",
        "naabu": "{\"host\":\"x\"}\n{\"port\":\"not-int\"}\n",
        "waybackurls": "\n\n   \n",
        "katana": "{\"request\":null}\n{}\n",
        "nuclei": "{\"info\":null}\n{\"template-id\":\"\"}\n",
        "uncover": "{\"port\":\"str\"}\n{\"ip\":\"not-an-ip\",\"port\":1}\n",
    }

    @pytest.mark.parametrize("name", sorted(CASES))
    def test_garbage_output_returns_empty_not_crash(self, tmp_path, name):
        tool = resolve_tool(name, [name])
        findings = tool.parse(_res(self.CASES[name]), _ctx(tmp_path))
        assert isinstance(findings, list)

    def test_unicode_titles_survive_parsing(self, tmp_path):
        tool = resolve_tool("httpx", ["httpx"])
        rec = ('{"url":"https://u.example.com","title":"\\u00dcber \\u2013 Site",'
               '"status_code":200}')
        (f,) = tool.parse(_res(rec), _ctx(tmp_path))
        assert f["title"].startswith("Über")

    def test_very_long_lines_do_not_break_parsers(self, tmp_path):
        tool = resolve_tool("subfinder", ["subfinder"])
        huge = '{"host":"' + "a" * 100000 + '.example.com"}'
        findings = tool.parse(_res(huge), _ctx(tmp_path))
        assert len(findings) == 1


class TestConfigParsing:
    def test_env_passthrough_list_parsed(self, monkeypatch):
        # Self-contained: provide the mandatory vars so this test does not
        # depend on the host environment (fail-fast is covered separately).
        monkeypatch.setenv("POSTGRES_PASSWORD", "test-pg")
        monkeypatch.setenv("MASTER_API_TOKEN", "test-token")
        monkeypatch.setenv("WORKER_ENV_PASSTHROUGH", "SHODAN_API_KEY, CHAOS_API_KEY ,,")
        s = load_settings()
        assert s.extra_env_keys == ["SHODAN_API_KEY", "CHAOS_API_KEY"]

    def test_missing_required_settings_fail_fast(self, monkeypatch):
        for var in ("MASTER_API_TOKEN", "POSTGRES_PASSWORD"):
            monkeypatch.delenv(var, raising=False)
        with pytest.raises(RuntimeError):
            load_settings()

    def test_test_settings_factory_isolated(self):
        s = make_test_settings()
        assert s.api_token == "test-token" and s.block_secs == 0


class TestNotificationFailures:
    def test_webhook_exception_never_raises(self, monkeypatch, tmp_path):
        from common import notifications as n

        monkeypatch.setenv("WEBHOOK_URL", "http://localhost:9/hook")

        def boom(*a, **kw):
            raise OSError("down")

        monkeypatch.setattr(n, "_post_json", boom)
        assert asyncio.run(n.notify_event("evt", {"x": 1})) is False

    def test_payload_shape(self, monkeypatch):
        from common import notifications as n

        captured = {}
        monkeypatch.setenv("WEBHOOK_URL", "http://hook")

        def fake_post(url, payload, timeout=5.0):
            captured.update(payload)
            return True

        monkeypatch.setattr(n, "_post_json", fake_post)
        assert asyncio.run(n.notify_event(
            "scan.finalized", details={"s": 1}, text="done")) is True
        assert captured["event"] == "scan.finalized"
        assert captured["text"] == "done"


class TestScopeBoundaries:
    def test_ipv6_cidr_scope_supported(self):
        from common.scope import ScopeEntry, evaluate

        entries = [ScopeEntry.parse("2001:db8::/32", True)]
        assert evaluate("2001:db8::1", entries).allowed
        assert not evaluate("2001:db9::1", entries).allowed

    def test_port_suffix_stripped_before_matching(self):
        from common.scope import evaluate, normalize_target, ScopeEntry

        entries = [ScopeEntry.parse("example.com", True)]
        # scheme/userinfo/port stripped by normalization before evaluation
        assert evaluate("user@https://example.com:8443/x", entries).allowed
