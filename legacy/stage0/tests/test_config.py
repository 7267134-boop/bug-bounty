"""Unit tests for configuration parsing and validation."""

import json

import pytest

from recon.config import ConfigError, ScanConfig, build_config, validate_domain


class TestDomainValidation:
    def test_valid_domain(self):
        assert validate_domain("Example.COM") == "example.com"

    def test_valid_subdomain_and_hyphen(self):
        assert validate_domain("api.dev-my-site.io") == "api.dev-my-site.io"

    def test_empty_raises(self):
        with pytest.raises(ConfigError):
            validate_domain("")

    @pytest.mark.parametrize("bad", [
        "not a domain", "-leading.com", "trailing-.com", "double..dot.com",
        "http://example.com", "exam ple.com", "a" * 250 + ".com",
    ])
    def test_invalid_formats_raise(self, bad):
        with pytest.raises(ConfigError):
            validate_domain(bad)


class TestBuildConfig:
    def test_defaults(self):
        cfg = build_config(overrides={"target_domain": "example.com"})
        assert isinstance(cfg, ScanConfig)
        assert cfg.enabled_tools == ["all"]
        assert cfg.max_retries == 3
        assert cfg.verbosity == "high"
        assert cfg.output_dir == "./reports"

    def test_json_config_file(self, tmp_path):
        path = tmp_path / "cfg.json"
        path.write_text(json.dumps({
            "target_domain": "example.org",
            "enabled_tools": ["nmap", "nuclei"],
            "max_retries": 2,
            "verbosity": "low",
            "output_dir": str(tmp_path / "out"),
        }))
        cfg = build_config(json_path=str(path))
        assert cfg.target_domain == "example.org"
        assert cfg.enabled_tools == ["nmap", "nuclei"]
        assert cfg.max_retries == 2
        assert cfg.verbosity == "low"

    def test_cli_overrides_json(self, tmp_path):
        path = tmp_path / "cfg.json"
        path.write_text(json.dumps({"target_domain": "json.com", "max_retries": 5}))
        args = type("Args", (), {"target_domain": "cli.com", "tools": None,
                                 "max_retries": 1, "tool_timeout_sec": None,
                                 "retry_delay_sec": None, "verbosity": None,
                                 "output_dir": None, "concurrency": None,
                                 "dry_run": False})()
        cfg = build_config(cli_args=args, json_path=str(path))
        assert cfg.target_domain == "cli.com"   # CLI wins
        assert cfg.max_retries == 1             # CLI wins
        assert cfg.enabled_tools == ["all"]     # JSON had none; default applies

    def test_missing_target_raises(self):
        with pytest.raises(ConfigError):
            build_config()

    def test_invalid_verbosity_raises(self):
        with pytest.raises(ConfigError):
            build_config(overrides={"target_domain": "a.com", "verbosity": "medium"})

    def test_negative_retries_raises(self):
        with pytest.raises(ConfigError):
            build_config(overrides={"target_domain": "a.com", "max_retries": -1})

    def test_comma_separated_tools_string(self):
        cfg = build_config(overrides={"target_domain": "a.com",
                                      "enabled_tools": "subfinder, nuclei"})
        assert cfg.enabled_tools == ["subfinder", "nuclei"]

    def test_extra_args(self):
        cfg = build_config(overrides={
            "target_domain": "a.com",
            "extra_args": {"nmap": ["-p", "80,443"]},
        })
        assert cfg.extra_args["nmap"] == ["-p", "80,443"]
