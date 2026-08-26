"""Profile Manager: configuration parsing, validation and merging.

Precedence: CLI arguments > JSON config file > built-in defaults.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

# RFC-1123-ish domain validation: labels of 1-63 alnum/hyphen chars, no leading
# or trailing hyphens, total length <= 253.
_DOMAIN_RE = r"^(?=.{1,253}\Z)(?!-)[A-Za-z0-9_-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*\Z"

import re

DOMAIN_REGEX = re.compile(_DOMAIN_RE)

VALID_VERBOSITY = ("high", "low")


class ConfigError(ValueError):
    """Raised for invalid user input. Maps to a CLI error (exit code 400)."""


@dataclass
class ScanConfig:
    """Fully resolved scan configuration."""

    target_domain: str
    enabled_tools: list[str] = field(default_factory=lambda: ["all"])
    max_retries: int = 3
    tool_timeout_sec: int = 3600
    retry_delay_sec: float = 2.0
    verbosity: str = "high"
    output_dir: str = "./reports"
    concurrency: int = 3
    extra_args: dict[str, list[str]] = field(default_factory=dict)
    dry_run: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_domain": self.target_domain,
            "enabled_tools": self.enabled_tools,
            "max_retries": self.max_retries,
            "tool_timeout_sec": self.tool_timeout_sec,
            "retry_delay_sec": self.retry_delay_sec,
            "verbosity": self.verbosity,
            "output_dir": self.output_dir,
            "concurrency": self.concurrency,
            "extra_args": self.extra_args,
            "dry_run": self.dry_run,
        }


def validate_domain(domain: str) -> str:
    """Validate the target domain format; raise ConfigError when invalid."""
    if not isinstance(domain, str) or not domain.strip():
        raise ConfigError("target_domain is required and must be a non-empty string")
    domain = domain.strip().lower().rstrip(".")
    if len(domain) > 253:
        raise ConfigError(f"target_domain exceeds maximum length of 253 characters: {domain!r}")
    if not DOMAIN_REGEX.match(domain):
        raise ConfigError(
            f"Invalid target domain format: {domain!r}. "
            "Expected a valid hostname such as 'example.com'."
        )
    return domain


def load_json_config(path: str) -> dict[str, Any]:
    """Load a JSON configuration file from disk."""
    if not os.path.isfile(path):
        raise ConfigError(f"Config file not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Config file {path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"Config file {path} must contain a JSON object at the top level")
    return data


def _coerce_int(value: Any, name: str, minimum: int) -> int:
    try:
        ivalue = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{name} must be an integer, got {value!r}") from exc
    if ivalue < minimum:
        raise ConfigError(f"{name} must be >= {minimum}, got {ivalue}")
    return ivalue


def build_config(
    cli_args: Any | None = None,
    json_path: str | None = None,
    overrides: dict[str, Any] | None = None,
) -> ScanConfig:
    """Build a ScanConfig by merging (in precedence order):

    defaults < JSON config file < ``cli_args`` namespace < ``overrides`` dict.
    """
    merged: dict[str, Any] = {}

    if json_path:
        merged.update(load_json_config(json_path))

    if cli_args is not None:
        for key in (
            "target_domain",
            "tools",
            "max_retries",
            "tool_timeout_sec",
            "retry_delay_sec",
            "verbosity",
            "output_dir",
            "concurrency",
            "dry_run",
        ):
            value = getattr(cli_args, key, None)
            if value is not None:
                mapped_key = "enabled_tools" if key == "tools" else key
                merged[mapped_key] = value

    if overrides:
        merged.update(overrides)

    domain = validate_domain(merged.get("target_domain"))

    enabled_tools = merged.get("enabled_tools") or ["all"]
    if isinstance(enabled_tools, str):
        enabled_tools = [t.strip() for t in enabled_tools.split(",") if t.strip()]
    if not isinstance(enabled_tools, list) or not all(isinstance(t, str) and t.strip() for t in enabled_tools):
        raise ConfigError("enabled_tools must be a list of tool names or ['all']")
    enabled_tools = [t.strip().lower() for t in enabled_tools]

    verbosity = str(merged.get("verbosity", "high")).lower()
    if verbosity not in VALID_VERBOSITY:
        raise ConfigError(f"verbosity must be one of {VALID_VERBOSITY}, got {verbosity!r}")

    output_dir = str(merged.get("output_dir", "./reports"))

    extra_raw = merged.get("extra_args") or {}
    if not isinstance(extra_raw, dict):
        raise ConfigError("extra_args must be an object mapping tool names to argument lists")

    return ScanConfig(
        target_domain=domain,
        enabled_tools=enabled_tools,
        max_retries=_coerce_int(merged.get("max_retries", 3), "max_retries", 1),
        tool_timeout_sec=_coerce_int(merged.get("tool_timeout_sec", 3600), "tool_timeout_sec", 1),
        retry_delay_sec=float(merged.get("retry_delay_sec", 2.0)),
        verbosity=verbosity,
        output_dir=output_dir,
        concurrency=_coerce_int(merged.get("concurrency", 3), "concurrency", 1),
        extra_args={
            str(k).lower(): [str(a) for a in v] for k, v in extra_raw.items()
        },
        dry_run=bool(merged.get("dry_run", False)),
    )
