"""Stage 3 — decision-engine routed tools.

Each wrapper here is triggered by a *routing signal* finding type emitted
by an earlier step, via ``when: {has_finding_type: <signal>}``:

  routing.bypass403  consumes http_403    → potential auth-bypass access
  wpscan             consumes wordpress   → CMS-specific enumeration
  corsy              consumes api_surface → CORS misconfiguration checks

All inherit the platform guarantees (argv-only, sandboxed, rate-limited,
scope-validated upstream input).
"""

from __future__ import annotations

import glob
import json
import os
import sys

from .base import ExecResult, ToolContext, ToolWrapper
from .registry import register
from .recon_enum import _dedupe

_BYPASS403_SCRIPT = r'''
import json, sys, ssl, urllib.request, urllib.error
ctx = ssl._create_unverified_context()
targets = [l.strip() for l in open(sys.argv[1], encoding="utf-8") if l.strip()]

def fetch(url, headers):
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None

for url in targets:
    base = fetch(url, {})
    if base is None or base < 400:
        continue                      # not blocked -> nothing to bypass
    scheme, _, rest = url.partition("://")
    host = rest.split("/")[0]
    path = "/" + rest[len(host):].lstrip("/")
    root = scheme + "://" + host
    variants = [
        ("x-original-url",  {"X-Original-URL": path},         url),
        ("x-rewrite-url",   {"X-Rewrite-URL": path},          url),
        ("xff-loopback",    {"X-Forwarded-For": "127.0.0.1"}, url),
        ("custom-ip-auth",  {"X-Custom-IP-Authorization": "127.0.0.1"}, url),
        ("referer-root",    {"Referer": root + "/"},          url),
        ("dot-slash",       {}, url.rstrip("/") + "/."),
        ("double-slash",    {}, root + "//" + rest[len(host):].lstrip("/")),
    ]
    for name, headers, target_url in variants:
        status = fetch(target_url, headers)
        if status is not None and 200 <= status < 403:
            print(json.dumps({"url": url, "technique": name,
                              "status": status,
                              "tested_url": target_url}))
'''


@register
class Bypass403Tool(ToolWrapper):
    """Header/path 403-bypass prover for URLs that answered 401/403.

    consumes: http_403     produces: vulnerability (id='bypass403')
    Only hits returning 2xx/3xx are reported; findings land as 'unvalidated'
    for human triage (Pillar B).
    """

    name = "routing.bypass403"
    binary = ""                          # builtin: runs via the interpreter
    description = "Proves/disproves 403 access-control using header & path tricks."
    produces = ["vulnerability"]
    consumes = ["http_403"]
    needs_input_file = True
    rate_limit_rps = 10.0

    def build_argv(self, ctx: ToolContext) -> list[str]:
        self.validate_params(ctx.params)
        return [sys.executable, "-c", _BYPASS403_SCRIPT, ctx.input_file or ""]

    def parse(self, result: ExecResult, ctx: ToolContext) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            url = str(rec.get("url", ""))
            technique = str(rec.get("technique", ""))
            status = rec.get("status")
            # Defense-in-depth: only genuine bypass statuses (2xx/3xx) count,
            # even if a malformed upstream ever fed us other codes.
            if not isinstance(status, int) or not (200 <= status < 403):
                continue
            value = f"bypass403:{technique}@{url}"
            if not url or value in seen:
                continue
            seen.add(value)
            findings.append({
                "type": "vulnerability",
                "id": "bypass403",
                "name": f"403 bypass via {technique}",
                "value": value,
                "severity": "medium",
                "matched_at": url,
                "tags": ["auth", "bypass", "403"],
                "evidence": {"technique": technique,
                             "status": rec.get("status"),
                             "tested_url": rec.get("tested_url")},
            })
        return _dedupe(findings, "value")

@register
class WpscanTool(ToolWrapper):
    """WordPress enumeration on hosts fingerprinted as WordPress.

    consumes: wordpress (URLs)   produces: vulnerability
    wpscan handles ONE --url per process, so this wrapper uses batch_mode:
    the executor runs one sandboxed wpscan per URL and merges the results.
    Optional API token via WORKER_ENV_PASSTHROUGH (WPSCAN_API_TOKEN).
    """

    name = "wpscan"
    binary = "wpscan"
    description = "WordPress core/plugin/theme vulnerability enumeration."
    produces = ["vulnerability"]
    consumes = ["wordpress"]
    needs_input_file = True
    batch_mode = True
    allowed_params = {"max_urls", "enumerate"}
    rate_limit_rps = 5.0

    def build_argv(self, ctx: ToolContext) -> list[str]:  # pragma: no cover
        raise NotImplementedError("use build_argv_batch")

    def build_argv_batch(self, ctx: ToolContext) -> list[list[str]]:
        params = self.validate_params(ctx.params)
        urls = (ctx.inputs.get("wordpress") or [])[:20]
        argvs: list[list[str]] = []
        token = os.environ.get("WPSCAN_API_TOKEN", "").strip()
        for i, url in enumerate(urls):
            outfile = os.path.join(ctx.workdir, f"wpscan_{i}.json")
            argv = [
                "wpscan", "--url", url,
                "--random-user-agent",
                "--enumerate", str(params.get("enumerate", "vp,vt")),
                "--format", "json", "-o", outfile,
            ]
            if token:
                argv += ["--api-token", token]
            argvs.append(argv)
        return argvs

    def parse(self, result: ExecResult, ctx: ToolContext) -> list[dict]:
        findings: list[dict] = []

        def walk(node: object, out: list[tuple[str, dict]]) -> None:
            if isinstance(node, dict):
                vulns = node.get("vulnerabilities")
                if isinstance(vulns, list):
                    slug = str(node.get("slug") or node.get("title") or "core")
                    for v in vulns:
                        if isinstance(v, dict):
                            out.append((slug, v))
                for child in node.values():
                    walk(child, out)
            elif isinstance(node, list):
                for child in node:
                    walk(child, out)

        for path in sorted(glob.glob(os.path.join(ctx.workdir,
                                                  "wpscan_*.json"))):
            try:
                with open(path, encoding="utf-8") as fh:
                    doc = json.load(fh)
            except (OSError, ValueError):
                continue
            pairs: list[tuple[str, dict]] = []
            walk(doc, pairs)
            target = str(doc.get("target_url") or "") if isinstance(doc, dict) else ""
            for slug, vuln in pairs:
                title = str(vuln.get("title") or f"wpscan-{slug}")
                cvss = None
                cvss_node = vuln.get("cvss")
                if isinstance(cvss_node, dict):
                    cvss = cvss_node.get("score")
                severity = str(vuln.get("severity") or "").lower()
                if severity not in ("critical", "high", "medium", "low", "info"):
                    severity = ("high" if isinstance(cvss, (int, float))
                                and cvss >= 7 else "medium")
                refs = vuln.get("references") or {}
                ref_urls = refs.get("url") or [] if isinstance(refs, dict) else []
                findings.append({
                    "type": "vulnerability",
                    "id": f"wpscan-{slug}",
                    "name": title,
                    "value": f"wpscan@{slug}@{title[:80]}",
                    "severity": severity,
                    "matched_at": target,
                    "tags": ["wordpress", "cms", "wpscan"],
                    "cvss_score": cvss,
                    "evidence": {
                        "fixed_in": vuln.get("fixed_in"),
                        "references": ref_urls[:5],
                    },
                })
        return findings


@register
class CorsyTool(ToolWrapper):
    """CORS misconfiguration scanner over discovered API surfaces.

    consumes: api_surface      produces: cors_misconfig
    """

    name = "corsy"
    binary = "/opt/corsy/corsy.py"       # cloned+chmod'ed in worker image
    description = "Detects CORS misconfigurations on API surfaces."
    produces = ["cors_misconfig"]
    consumes = ["api_surface"]
    needs_input_file = True
    allowed_params = {"threads"}
    rate_limit_rps = 10.0

    def check_binary(self) -> bool:
        return os.path.exists(self.binary)

    def build_argv(self, ctx: ToolContext) -> list[str]:
        params = self.validate_params(ctx.params)
        return [
            sys.executable, self.binary,
            "-i", ctx.input_file or "",
            "-t", str(max(1, int(params.get("threads", 10)))),
        ]

    def parse(self, result: ExecResult, ctx: ToolContext) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        for line in result.stdout.splitlines():
            line = line.strip()
            if "cors" not in line.lower() or len(line) < 12:
                continue
            value = line[:300]
            if value in seen:
                continue
            seen.add(value)
            findings.append({"type": "cors_misconfig", "value": value,
                             "severity": "low"})
        return _dedupe(findings, "value")


