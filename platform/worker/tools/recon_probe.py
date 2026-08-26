"""Resolution & port-enrichment wrappers (massdns / nmap).

Routing contract (cost-first design):
    subfinder/assetfinder ─► massdns ─► resolved_host ─► httpx / naabu
                                          │
                                          └─► open_port ─► nmap (-sV -sC,
                                                only discovered ports)

Dead domains never reach the HTTP probers; deep service enumeration runs
only against ports naabu actually found open.
"""

from __future__ import annotations

import os

import json  # noqa: F401  (used by parsers below via _json_lines consumers)

from .base import (ExecResult, ToolContext, ToolExecutionError,  # noqa: F401
                   ToolWrapper)
from .registry import register
from .recon_enum import _dedupe, _json_lines  # noqa: F401

# Curated high-reliability public resolvers shipped with the worker image.
RESOLVERS_PATH = "/app/worker/assets/resolvers.txt"


@register
class MassdnsTool(ToolWrapper):
    """High-performance bulk DNS resolution — the dead-domain filter.

    consumes: subdomain        produces: resolved_host
    Unresolvable names are dropped HERE so neither httpx nor naabu wastes
    requests on them (the core resource-saving rule of Stage 2).
    """

    name = "massdns"
    binary = "massdns"
    description = ("Bulk DNS resolution with public resolvers; drops dead "
                   "domains before probing.")
    produces = ["resolved_host"]
    consumes = ["subdomain"]
    needs_input_file = True
    rate_limit_rps = 50.0

    def build_argv(self, ctx: ToolContext) -> list[str]:
        self.validate_params(ctx.params)
        return [
            "massdns", "-r", RESOLVERS_PATH,
            "-o", "S",              # simple output: one resolved name per line
            "--silent", "--flush",
            ctx.input_file or "",
        ]

    def parse(self, result: ExecResult, ctx: ToolContext) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        for line in result.stdout.splitlines():
            host = line.strip().lower().rstrip(".")
            if not host or "." not in host or host.startswith(("#", ";")):
                continue
            if host in seen:
                continue
            seen.add(host)
            findings.append({"type": "resolved_host", "value": host})
        return findings


@register
class NmapTool(ToolWrapper):
    """Targeted service/version enumeration — never a blind 65k-port sweep.

    consumes: open_port (host:port values from naabu)
    produces: service

    The wrapper aggregates the union of ports found by naabu and points
    nmap at exactly those ports on exactly the affected hosts
    (``-sV -sC -p <union> -iL <hosts>``), minimising noise and scan time.
    """

    name = "nmap"
    binary = "nmap"
    description = "Deep service/version scan restricted to discovered ports."
    produces = ["service", "exposed_service"]
    consumes = ["open_port"]
    needs_input_file = True
    rate_limit_rps = 5.0

    @staticmethod
    def _split_open_ports(values: list[str]) -> tuple[list[str], list[str]]:
        hosts: list[str] = []
        ports: set[int] = set()
        for value in values:
            _, _, port_part = value.rpartition(":")
            try:
                ports.add(int(port_part))
            except ValueError:
                continue
            host = value[: len(value) - len(port_part) - 1]
            if host and host not in hosts:
                hosts.append(host)
        return hosts, sorted(ports)

    def build_argv(self, ctx: ToolContext) -> list[str]:
        self.validate_params(ctx.params)
        values = []
        for ftype in self.consumes:
            values.extend(ctx.inputs.get(ftype, []))
        hosts, ports = self._split_open_ports(values)
        if not hosts or not ports:
            raise ToolExecutionError("nmap: no open ports to enumerate")
        hosts_file = os.path.join(ctx.workdir, "hosts.txt")
        with open(hosts_file, "w", encoding="utf-8") as fh:
            fh.write("\n".join(hosts) + "\n")
        return [
            "nmap", "-Pn",
            "-sV", "-sC",                       # deep enumeration, targeted
            "-p", ",".join(str(p) for p in ports),
            "-iL", hosts_file,
            "-oG", "-",                          # greppable stdout, no files
            "--open",
        ]

    def parse(self, result: ExecResult, ctx: ToolContext) -> list[dict]:
        import re

        status_re = re.compile(r"(\d+)/(\w+)/(\w+)//([^/]*?)(?:/([^,]*?))?(?=[,\t])")
        findings: list[dict] = []
        seen: set[str] = set()
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line.startswith("Host:"):
                continue
            host_part, _, ports_part = line.partition("Ports:")
            host = host_part.replace("Host:", "").split("(")[0].strip()
            for match in status_re.finditer(ports_part):
                port, state, _proto, service, version = match.groups()
                if state.lower() != "open":
                    continue
                value = f"{host}:{port} {service}".strip()
                if value in seen:
                    continue
                seen.add(value)
                findings.append({
                    "type": "service",
                    "value": value,
                    "host": host,
                    "port": int(port),
                    "service": service or "unknown",
                    "version": (version or "").strip().strip("/").strip(),
                })
        # ── Routing signal (Stage 3): exposed data-store / infra services ──
        _RISKY_PORTS = {"3306", "5432", "6379", "27017", "1433", "9200", "21"}
        for f in list(findings):
            if str(f["port"]) in _RISKY_PORTS:
                findings.append({
                    "type": "exposed_service",
                    "value": f["value"],
                    "host": f["host"],
                    "port": f["port"],
                    "service": f["service"],
                })
        return findings


@register
class DnsxTool(ToolWrapper):
    name = "dnsx"
    binary = "dnsx"
    description = "DNS resolution + wildcard filtering for discovered subdomains."
    produces = ["ip"]
    consumes = ["subdomain"]
    needs_input_file = True
    rate_limit_rps = 50.0

    def build_argv(self, ctx: ToolContext) -> list[str]:
        self.validate_params(ctx.params)
        return ["dnsx", "-l", ctx.input_file or "", "-json", "-resp", "-silent"]

    def parse(self, result: ExecResult, ctx: ToolContext) -> list[dict]:
        findings: list[dict] = []
        for rec in _json_lines(result.stdout):
            host = str(rec.get("host", "")).strip().lower()
            for record_type in ("a", "aaaa"):
                for ip in rec.get(record_type) or []:
                    findings.append({"type": "ip", "value": str(ip),
                                     "hostname": host})
        return _dedupe(findings, "value")


@register
class HttpxTool(ToolWrapper):
    name = "httpx"
    binary = "httpx"
    description = "HTTP probe of live hosts with title/tech/status enrichment."
    produces = ["live_host", "wordpress", "http_403", "login_page",
                "api_surface"]   # routing signals for the decision engine
    consumes = ["resolved_host"]            # R1: dead domains never probed
    needs_input_file = True
    rate_limit_rps = 30.0

    def build_argv(self, ctx: ToolContext) -> list[str]:
        params = self.validate_params(ctx.params)
        argv = [
            "httpx", "-l", ctx.input_file or "", "-json", "-silent",
            "-title", "-tech-detect", "-status-code", "-webserver",
            "-no-color", "-random-agent",
            "-rl", str(max(1, min(int(ctx.rate_limit_rps), 300))),
        ]
        if params.get("threads"):
            argv += ["-t", str(int(params["threads"]))]
        return argv

    def parse(self, result: ExecResult, ctx: ToolContext) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        for rec in _json_lines(result.stdout):
            url = str(rec.get("url") or rec.get("input") or "").strip()
            if not url or url in seen:
                continue
            seen.add(url)
            tech = rec.get("tech") or rec.get("technologies") or []
            if isinstance(tech, str):
                tech = [tech]
            title = str(rec.get("title") or "")
            findings.append({
                "type": "live_host",
                "value": url,
                "status_code": rec.get("status_code"),
                "title": title,
                "technologies": tech,
                "webserver": rec.get("webserver"),
            })
            # ── Routing signals (Stage 3 decision engine) ────────────────
            haystack = " ".join([*map(str, tech), title]).lower()
            if "wordpress" in haystack:
                findings.append({"type": "wordpress", "value": url})
            status = rec.get("status_code")
            if status in (401, 403):
                findings.append({"type": "http_403", "value": url,
                                 "status_code": status})
            lowered_title = title.lower()
            path_only = url.lower().split("?")[0]
            if ("login" in lowered_title or "log in" in lowered_title
                    or "sign in" in lowered_title
                    or path_only.rstrip("/").endswith(("login", "signin"))):
                findings.append({"type": "login_page", "value": url})
            if "/api/" in path_only:
                findings.append({"type": "api_surface", "value": url})
        return findings


@register
class NaabuTool(ToolWrapper):
    name = "naabu"
    binary = "naabu"
    description = "Fast top-1000 TCP port discovery (unprivileged connect scan)."
    produces = ["open_port"]
    consumes = ["resolved_host"]     # R1: dead domains never scanned
    needs_input_file = True
    rate_limit_rps = 20.0

    def build_argv(self, ctx: ToolContext) -> list[str]:
        self.validate_params(ctx.params)
        # '-s connect' keeps the scan usable inside an unprivileged container.
        return [
            "naabu", "-l", ctx.input_file or "", "-json", "-silent",
            "-s", "connect", "-top-ports", "1000", "-exclude-cdn",
        ]

    def parse(self, result: ExecResult, ctx: ToolContext) -> list[dict]:
        findings: list[dict] = []
        for rec in _json_lines(result.stdout):
            port = rec.get("port")
            if not isinstance(port, int):
                continue
            host = str(rec.get("host") or rec.get("ip") or "").strip().lower()
            if not host:
                continue
            findings.append({
                "type": "open_port",
                "value": f"{host}:{port}",
                "host": host,
                "port": port,
            })
        return _dedupe(findings, "value")
