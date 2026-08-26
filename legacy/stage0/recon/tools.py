"""Tool registry: defines every supported Kali tool, its CLI arguments and
its pipeline stage.

Stages allow dependency-aware parallel execution:
  stage 1: passive subdomain enumeration + host/port scanning (independent)
  stage 2: live-host probing (depends on discovered subdomains)
  stage 3: vulnerability scanning (depends on live hosts)
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolSpec:
    name: str
    binary: str
    description: str
    stage: int
    parser_name: str | None = None
    # Optional file inputs produced by earlier stages. Keys become format
    # placeholders available to build_args via ctx["files"].
    requires_files: list[str] = field(default_factory=list)
    build_args: Any = None  # callable(config, ctx) -> list[str]

    def resolve_binary(self) -> str | None:
        """Return absolute path of the binary if present in $PATH, else None."""
        return shutil.which(self.binary)


def _subfinder_args(config, ctx):
    return ["-d", config.target_domain] + config.extra_args.get("subfinder", [])


def _assetfinder_args(config, ctx):
    return ["--subs-only", config.target_domain] + config.extra_args.get("assetfinder", [])


def _amass_args(config, ctx):
    return ["enum", "-passive", "-d", config.target_domain] + config.extra_args.get("amass", [])


def _nmap_args(config, ctx):
    return [
        "-Pn",
        "-sV",
        "-T4",
        "--top-ports",
        "1000",
        "-oG",
        "-",
        config.target_domain,
    ] + config.extra_args.get("nmap", [])


def _naabu_args(config, ctx):
    return ["-host", config.target_domain] + config.extra_args.get("naabu", [])


def _httpx_args(config, ctx):
    args = [
        "-l",
        ctx["files"]["subdomains"],
        "-json",
        "-title",
        "-tech-detect",
        "-status-code",
        "-silent",
    ]
    return args + config.extra_args.get("httpx", [])


def _nuclei_args(config, ctx):
    args = [
        "-l",
        ctx["files"]["live_hosts"],
        "-json",
        "-nc",
        "-silent",
    ]
    return args + config.extra_args.get("nuclei", [])


TOOL_SPECS: dict[str, ToolSpec] = {
    spec.name: spec
    for spec in (
        ToolSpec(
            name="subfinder",
            binary="subfinder",
            description="Passive subdomain enumeration (projectdiscovery).",
            stage=1,
            parser_name="subfinder",
            build_args=_subfinder_args,
        ),
        ToolSpec(
            name="assetfinder",
            binary="assetfinder",
            description="Subdomain discovery via certificate transparency logs.",
            stage=1,
            parser_name="assetfinder",
            build_args=_assetfinder_args,
        ),
        ToolSpec(
            name="amass",
            binary="amass",
            description="OWASP Amass passive subdomain enumeration.",
            stage=1,
            parser_name="amass",
            build_args=_amass_args,
        ),
        ToolSpec(
            name="nmap",
            binary="nmap",
            description="Service/version scan of top 1000 ports on the target.",
            stage=1,
            parser_name="nmap",
            build_args=_nmap_args,
        ),
        ToolSpec(
            name="naabu",
            binary="naabu",
            description="Fast port scanner (projectdiscovery).",
            stage=1,
            parser_name="naabu",
            build_args=_naabu_args,
        ),
        ToolSpec(
            name="httpx",
            binary="httpx",
            description="Probe discovered subdomains for live HTTP services.",
            stage=2,
            parser_name="httpx",
            requires_files=["subdomains"],
            build_args=_httpx_args,
        ),
        ToolSpec(
            name="nuclei",
            binary="nuclei",
            description="Template-driven vulnerability scanning on live hosts.",
            stage=3,
            parser_name="nuclei",
            requires_files=["live_hosts"],
            build_args=_nuclei_args,
        ),
    )
}


def expand_tool_selection(enabled_tools: list[str]) -> list[ToolSpec]:
    """Expand an 'all'/mixed selection into ordered ToolSpec objects.

    Raises KeyError for unknown tool names.
    """
    if "all" in enabled_tools:
        return sorted(TOOL_SPECS.values(), key=lambda s: s.stage)
    selected: list[ToolSpec] = []
    for name in enabled_tools:
        spec = TOOL_SPECS.get(name.lower())
        if spec is None:
            raise KeyError(name)
        selected.append(spec)
    return sorted(selected, key=lambda s: s.stage)
