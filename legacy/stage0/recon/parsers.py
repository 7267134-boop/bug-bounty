"""Tool output parsers (Strategy Pattern).

Each parser normalizes the raw STDOUT of one security tool into a list of
finding dictionaries that feed the Unified Vulnerability Schema.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from typing import Callable


class BaseParser(ABC):
    """Base class every tool parser must inherit from."""

    tool_name: str = "base"

    @abstractmethod
    def parse(self, stdout: str, stderr: str, target: str) -> list[dict]:
        """Return a list of normalized finding dicts."""


class LineParser(BaseParser):
    """Parses plain-text line based output (one finding per non-empty line)."""

    tool_name = "line"
    finding_type = "unknown"
    value_key = "value"

    def parse(self, stdout: str, stderr: str, target: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        for line in stdout.splitlines():
            value = line.strip()
            if not value or value in seen:
                continue
            seen.add(value)
            findings.append({"type": self.finding_type, self.value_key: value, "source_target": target})
        return findings


class SubfinderParser(LineParser):
    tool_name = "subfinder"
    finding_type = "subdomain"
    value_key = "subdomain"


class AssetfinderParser(LineParser):
    tool_name = "assetfinder"
    finding_type = "subdomain"
    value_key = "subdomain"


class AmassParser(LineParser):
    tool_name = "amass"
    finding_type = "subdomain"
    value_key = "subdomain"


class NaabuParser(LineParser):
    """naabu emits ``host:port`` lines (plain mode)."""

    tool_name = "naabu"
    finding_type = "open_port"
    value_key = "host_port"

    _HOSTPORT_RE = re.compile(r"^(?P<host>[^:]+):(?P<port>\d+)$")

    def parse(self, stdout: str, stderr: str, target: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[tuple[str, int]] = set()
        for line in stdout.splitlines():
            match = self._HOSTPORT_RE.match(line.strip())
            if not match:
                continue
            key = (match.group("host"), int(match.group("port")))
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "type": "open_port",
                    "host": key[0],
                    "port": key[1],
                    "source_target": target,
                }
            )
        return findings


class HttpxParser(BaseParser):
    """Parses projectdiscovery httpx JSON-lines output (``httpx -json``)."""

    tool_name = "httpx"

    def parse(self, stdout: str, stderr: str, target: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = record.get("url") or record.get("input") or ""
            if not url or url in seen:
                continue
            seen.add(url)
            tech = record.get("tech") or record.get("technologies") or []
            if isinstance(tech, str):
                tech = [tech]
            findings.append(
                {
                    "type": "live_host",
                    "url": url,
                    "status_code": record.get("status_code"),
                    "title": record.get("title"),
                    "host": record.get("host") or record.get("input"),
                    "technologies": tech,
                    "webserver": record.get("webserver"),
                    "source_target": target,
                }
            )
        return findings


class NucleiParser(BaseParser):
    """Parses nuclei JSON-lines output (``nuclei -json``)."""

    tool_name = "nuclei"

    SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")

    def parse(self, stdout: str, stderr: str, target: str) -> list[dict]:
        findings: list[dict] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = record.get("info") if isinstance(record.get("info"), dict) else {}
            classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
            severity = str(info.get("severity", "unknown")).lower()
            if severity not in self.SEVERITIES:
                severity = "unknown"
            findings.append(
                {
                    "type": "vulnerability",
                    "id": record.get("template-id") or record.get("templateID") or info.get("name") or "unknown",
                    "name": info.get("name") or record.get("template-id") or "unknown",
                    "severity": severity,
                    "matched_at": record.get("matched-at") or record.get("matched") or record.get("host"),
                    "matcher_status": record.get("matcher-status"),
                    "description": info.get("description"),
                    "tags": info.get("tags") or [],
                    "cve_ids": classification.get("cve-id") or [],
                    "cwe_ids": classification.get("cwe-id") or [],
                    "cvss_score": classification.get("cvss-score"),
                    "reference_urls": (info.get("reference") or [])[:5],
                    "curl_command": record.get("curl-command"),
                    "source_target": target,
                }
            )
        return findings


class NmapParser(BaseParser):
    """Parses nmap greppable output (``nmap -oG -``)."""

    tool_name = "nmap"

    _STATUS_RE = re.compile(r"(\d+)/(\w+)/(\w+)//([^/]*?)(?:/([^,]*?))?(?=[,\t])")

    def parse(self, stdout: str, stderr: str, target: str) -> list[dict]:
        findings: list[dict] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("Host:") or "Ports:" not in line:
                continue
            host_part, _, ports_part = line.partition("Ports:")
            host = host_part.replace("Host:", "").split("(")[0].strip()
            interesting = re.search(r"\((.*?)\)", host_part)
            hostname = interesting.group(1) if interesting else ""
            open_ports = []
            for match in self._STATUS_RE.finditer(ports_part):
                port, state, proto, service, version = match.groups()
                if state.lower() == "open":
                    open_ports.append(
                        {
                            "port": int(port),
                            "protocol": proto,
                            "service": service or "unknown",
                            "version": (version or "").strip().strip("/").strip(),
                        }
                    )
            if open_ports:
                findings.append(
                    {
                        "type": "host_ports",
                        "host": host or target,
                        "hostname": hostname,
                        "ports": open_ports,
                        "source_target": target,
                    }
                )
        return findings


PARSERS: dict[str, Callable[[], BaseParser]] = {
    cls.tool_name: cls
    for cls in (
        SubfinderParser,
        AssetfinderParser,
        AmassParser,
        NaabuParser,
        HttpxParser,
        NucleiParser,
        NmapParser,
    )
}


def get_parser(tool_name: str) -> BaseParser | None:
    """Return a fresh parser instance for *tool_name*, or None if unsupported."""
    cls = PARSERS.get(tool_name.lower())
    return cls() if cls else None


def parse_findings(tool_name: str, stdout: str, stderr: str, target: str) -> list[dict]:
    parser = get_parser(tool_name)
    if parser is None:
        # No dedicated parser: keep raw lines as generic findings so no data is lost.
        return LineParser().parse(stdout, stderr, target)
    try:
        return parser.parse(stdout, stderr, target)
    except Exception:  # noqa: BLE001 - parsing must never crash the pipeline
        return []


