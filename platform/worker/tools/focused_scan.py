"""Stage 4 — focused scanning wrappers (ffuf / arjun / sqlmap / trufflehog).

All of these are *expensive* tools, so every one is behind a routing gate
(``when.has_finding_type``) and consumes only what cheaper recon produced:

    ffuf        live_host            → discovered_url     (content discovery)
    arjun       live_host/api_surface→ url_param          (hidden parameters)
    sqlmap      url_param            → vulnerability      (SQLi, batch -m)
    trufflehog  js_url               → secret             (JS secret sweep)

Security notes:
  * sqlmap is gated to ``url_param`` and ships with conservative defaults;
    operators should prefer running it AFTER human triage.
  * trufflehog hits are REDACTED before storage: the platform keeps the
    detector + location + a short preview, never the full secret.
"""

from __future__ import annotations

import glob
import json
import os
import sys

from .base import ExecResult, ToolContext, ToolExecutionError, ToolWrapper
from .registry import register
from .recon_enum import _dedupe

# Small built-in wordlist so ffuf works out-of-the-box. Mount SecLists at
# /usr/share/seclists and pass params.wordlist for production sweeps.
FALLBACK_WORDLIST = os.path.normpath(
    os.path.join(os.path.dirname(__file__), os.pardir, "assets",
                 "wordlist_common.txt")
)
DEFAULT_SECLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"

@register
class FfufTool(ToolWrapper):
    """Content discovery per live host — batch mode (FUZZ is per-URL)."""

    name = "ffuf"
    binary = "ffuf"
    description = "Directory/parameter content discovery (one run per host)."
    produces = ["discovered_url"]
    consumes = ["live_host"]
    needs_input_file = False          # inputs consumed via build_argv_batch
    batch_mode = True
    allowed_params = {"wordlist", "threads"}
    rate_limit_rps = 40.0

    def _resolve_wordlist(self, params: dict) -> str:
        candidate = str(params.get("wordlist") or DEFAULT_SECLIST)
        if os.path.isfile(candidate):
            return candidate
        if os.path.isfile(FALLBACK_WORDLIST):
            return FALLBACK_WORDLIST
        raise ToolExecutionError(
            f"wordlist not found: {candidate} (and no fallback at "
            f"{FALLBACK_WORDLIST})"
        )

    def build_argv(self, ctx: ToolContext) -> list[str]:  # pragma: no cover
        raise NotImplementedError("use build_argv_batch")

    def build_argv_batch(self, ctx: ToolContext) -> list[list[str]]:
        params = self.validate_params(ctx.params)
        wordlist = self._resolve_wordlist(params)
        urls = [u for t in self.consumes for u in ctx.inputs.get(t, [])]
        argvs: list[list[str]] = []
        for i, url in enumerate(urls[:50]):          # hard cap per task
            target = url if url.endswith("/") else url + "/"
            outfile = os.path.join(ctx.workdir, f"ffuf_{i}.json")
            argvs.append([
                "ffuf",
                "-w", f"{wordlist}:FUZZ",
                "-u", target + "FUZZ",
                "-mc", "200,204,301,302,307,401,403",
                "-ac",                                # auto-calibrate filters
                "-t", str(max(1, int(params.get("threads", 20)))),
                "-of", "json", "-o", outfile,
                "-s",
            ])
        return argvs

    def parse(self, result: ExecResult, ctx: ToolContext) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        for path in sorted(glob.glob(os.path.join(ctx.workdir, "ffuf_*.json"))):
            try:
                with open(path, encoding="utf-8") as fh:
                    doc = json.load(fh)
            except (OSError, ValueError):
                continue
            for hit in doc.get("results") or []:
                url = str(hit.get("url") or "").strip()
                if not url or url in seen:
                    continue
                seen.add(url)
                findings.append({
                    "type": "discovered_url",
                    "value": url,
                    "status_code": hit.get("status"),
                    "length": hit.get("length"),
                    "words": hit.get("words"),
                })
        return findings


@register
class ArjunTool(ToolWrapper):
    """Hidden HTTP parameter discovery over live hosts / API surfaces."""

    name = "arjun"
    binary = "arjun"
    description = "Hidden parameter discovery (heuristic + reflection)."
    produces = ["url_param"]
    consumes = ["live_host", "api_surface"]
    needs_input_file = True
    allowed_params = {"threads"}
    rate_limit_rps = 10.0

    def build_argv(self, ctx: ToolContext) -> list[str]:
        params = self.validate_params(ctx.params)
        return [
            "arjun", "-i", ctx.input_file or "",
            "-oJ", os.path.join(ctx.workdir, "arjun.json"),
            "--stable",
            "-t", str(max(1, int(params.get("threads", 5)))),
        ]

    def parse(self, result: ExecResult, ctx: ToolContext) -> list[dict]:
        out_path = os.path.join(ctx.workdir, "arjun.json")
        if not os.path.isfile(out_path):
            return []
        try:
            with open(out_path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError):
            return []
        if not isinstance(doc, dict):
            return []
        findings: list[dict] = []
        seen: set[str] = set()
        for endpoint, param_map in doc.items():
            if not isinstance(param_map, dict):
                continue
            base = endpoint.split("?")[0]
            for param in param_map:
                value = f"{base}?{param}=<fuzz>"
                if value in seen:
                    continue
                seen.add(value)
                findings.append({"type": "url_param", "url": value,
                                 "value": value, "param": param})
        return findings

@register
class FfufTool(ToolWrapper):
    """Content discovery per live host — batch mode (FUZZ is per-URL)."""

    name = "ffuf"
    binary = "ffuf"
    description = "Directory/parameter content discovery (one run per host)."
    produces = ["discovered_url"]
    consumes = ["live_host"]
    needs_input_file = False          # inputs consumed via build_argv_batch
    batch_mode = True
    allowed_params = {"wordlist", "threads"}
    rate_limit_rps = 40.0

    def _resolve_wordlist(self, params: dict) -> str:
        candidate = str(params.get("wordlist") or DEFAULT_SECLIST)
        if os.path.isfile(candidate):
            return candidate
        if os.path.isfile(FALLBACK_WORDLIST):
            return FALLBACK_WORDLIST
        raise ToolExecutionError(
            f"wordlist not found: {candidate} (and no fallback at "
            f"{FALLBACK_WORDLIST})"
        )

    def build_argv(self, ctx: ToolContext) -> list[str]:  # pragma: no cover
        raise NotImplementedError("use build_argv_batch")

    def build_argv_batch(self, ctx: ToolContext) -> list[list[str]]:
        params = self.validate_params(ctx.params)
        wordlist = self._resolve_wordlist(params)
        urls = [u for t in self.consumes for u in ctx.inputs.get(t, [])]
        argvs: list[list[str]] = []
        for i, url in enumerate(urls[:50]):          # hard cap per task
            target = url if url.endswith("/") else url + "/"
            outfile = os.path.join(ctx.workdir, f"ffuf_{i}.json")
            argvs.append([
                "ffuf",
                "-w", f"{wordlist}:FUZZ",
                "-u", target + "FUZZ",
                "-mc", "200,204,301,302,307,401,403",
                "-ac",                                # auto-calibrate filters
                "-t", str(max(1, int(params.get("threads", 20)))),
                "-of", "json", "-o", outfile,
                "-s",
            ])
        return argvs

    def parse(self, result: ExecResult, ctx: ToolContext) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        for path in sorted(glob.glob(os.path.join(ctx.workdir, "ffuf_*.json"))):
            try:
                with open(path, encoding="utf-8") as fh:
                    doc = json.load(fh)
            except (OSError, ValueError):
                continue
            for hit in doc.get("results") or []:
                url = str(hit.get("url") or "").strip()
                if not url or url in seen:
                    continue
                seen.add(url)
                findings.append({
                    "type": "discovered_url",
                    "value": url,
                    "status_code": hit.get("status"),
                    "length": hit.get("length"),
                    "words": hit.get("words"),
                })
        return findings

@register
class ArjunTool(ToolWrapper):
    """Hidden HTTP parameter discovery over live hosts / API surfaces."""

    name = "arjun"
    binary = "arjun"
    description = "Hidden parameter discovery (heuristic + reflection)."
    produces = ["url_param"]
    consumes = ["live_host", "api_surface"]
    needs_input_file = True
    allowed_params = {"threads"}
    rate_limit_rps = 10.0

    def build_argv(self, ctx: ToolContext) -> list[str]:
        params = self.validate_params(ctx.params)
        return [
            "arjun", "-i", ctx.input_file or "",
            "-oJ", os.path.join(ctx.workdir, "arjun.json"),
            "--stable",
            "-t", str(max(1, int(params.get("threads", 5)))),
        ]

    def parse(self, result: ExecResult, ctx: ToolContext) -> list[dict]:
        out_path = os.path.join(ctx.workdir, "arjun.json")
        if not os.path.isfile(out_path):
            return []
        try:
            with open(out_path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError):
            return []
        if not isinstance(doc, dict):
            return []
        findings: list[dict] = []
        seen: set[str] = set()
        for endpoint, param_map in doc.items():
            if not isinstance(param_map, dict):
                continue
            base = endpoint.split("?")[0]
            for param in param_map:
                value = f"{base}?{param}=<fuzz>"
                if value in seen:
                    continue
                seen.add(value)
                findings.append({"type": "url_param", "url": value,
                                 "value": value, "param": param})
        return findings

@register
class SqlmapTool(ToolWrapper):
    """SQLi validation on discovered parameterized URLs.

    consumes: url_param            produces: vulnerability

    SAFETY: conservative defaults (--level=1 --risk=1 --batch), capped to 10
    URLs per task. Operators should normally run this AFTER human triage has
    confirmed the parameter is interesting (Pillar B), not blindly.
    """

    name = "sqlmap"
    binary = "sqlmap"
    description = "SQL injection validation (conservative, batch mode)."
    produces = ["vulnerability"]
    consumes = ["url_param"]
    needs_input_file = True
    batch_mode = True
    allowed_params = {"level", "risk", "max_urls"}
    rate_limit_rps = 2.0

    _PARAM_RE = None  # compiled lazily (class-level cache)

    @classmethod
    def _extract_injections(cls, stdout: str) -> list[dict]:
        import re

        if cls._PARAM_RE is None:
            cls._PARAM_RE = re.compile(
                r"(\w+)\s+parameter\s+'([^']+)'\s+is\s+vulnerable", re.I
            )
        return [
            {"method": m.group(1).upper(), "param": m.group(2)}
            for m in cls._PARAM_RE.finditer(stdout)
        ]

    def build_argv(self, ctx: ToolContext) -> list[str]:  # pragma: no cover
        raise NotImplementedError("use build_argv_batch")

    def build_argv_batch(self, ctx: ToolContext) -> list[list[str]]:
        params = self.validate_params(ctx.params)
        urls = (ctx.inputs.get("url_param") or [])[:10]
        outdir = os.path.join(ctx.workdir, "sqlmap-out")
        argvs: list[list[str]] = []
        for i, url in enumerate(urls):
            argvs.append([
                "sqlmap", "-u", url,
                "--batch", "--disable-coloration",
                "--level", str(int(params.get("level", 1))),
                "--risk", str(int(params.get("risk", 1))),
                "--threads", "3",
                "--output-dir", os.path.join(outdir, str(i)),
                "--flush-session",
            ])
        return argvs

    def parse(self, result: ExecResult, ctx: ToolContext) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        for inj in self._extract_injections(result.stdout):
            method, param = inj["method"], inj["param"]
            value = f"sqlmap@{method.lower()}@{param}"
            if value in seen:
                continue
            seen.add(value)
            findings.append({
                "type": "vulnerability",
                "id": "sqlmap-sqli",
                "name": f"SQL injection ({method} param '{param}')",
                "value": value,
                "severity": "high",
                "matched_at": ctx.target or "(multi)",
                "tags": ["sqli", "sqlmap"],
                "evidence": {"parameter": param, "method": method},
            })
        return findings

@register
class TrufflehogTool(ToolWrapper):
    """Secret sweep over crawled JavaScript files.

    consumes: js_url              produces: secret

    A builtin python driver downloads each .js URL into the task tmpfs
    (count + size capped), then execs ``trufflehog filesystem <dir> --json``.
    Hits are REDACTED before storage: the platform keeps the detector name,
    the source file and a 12-char preview — never the full secret.
    """

    name = "trufflehog"
    binary = "trufflehog"
    description = "Verified secret detection across downloaded JS assets."
    produces = ["secret"]
    consumes = ["js_url"]
    needs_input_file = True
    allowed_params = {"max_files", "max_file_bytes"}
    rate_limit_rps = 5.0

    MAX_FILES_DEFAULT = 50
    MAX_FILE_BYTES = 512 * 1024

    def build_argv(self, ctx: ToolContext) -> list[str]:
        params = self.validate_params(ctx.params)
        max_files = int(params.get("max_files", self.MAX_FILES_DEFAULT))
        max_bytes = int(params.get("max_file_bytes", self.MAX_FILE_BYTES))
        driver = (
            "import os,subprocess,sys,urllib.request,ssl\n"
            f"MAX_FILES={max_files};MAX_BYTES={max_bytes}\n"
            "urls=[l.strip() for l in open(sys.argv[1],encoding='utf-8') "
            "if l.strip()][:MAX_FILES]\n"
            "d=os.path.join(sys.argv[2],'js'); os.makedirs(d,exist_ok=True)\n"
            "c=0; cx=ssl._create_unverified_context()\n"
            "for u in urls:\n"
            "    name=''.join(ch for ch in u.split('/')[-1].split('?')[0] "
            "if ch.isalnum() or ch in '._-')[:80] or ('f%d.js'%c)\n"
            "    try:\n"
            "        data=urllib.request.urlopen(u,timeout=15,context=cx)"
            ".read(MAX_BYTES)\n"
            "        if data: open(os.path.join(d,name),'wb').write(data); c+=1\n"
            "    except Exception: pass\n"
            "if c==0:\n"
            "    print('no js files downloaded'); sys.exit(3)\n"
            "sys.exit(subprocess.run(['trufflehog','filesystem',d,'--json',"
            "'--no-update','--only-verified']).returncode)\n"
        )
        return [sys.executable, "-c", driver,
                ctx.input_file or "", ctx.workdir]

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
            detector = str(rec.get("DetectorName") or "unknown")
            raw = str(rec.get("Raw") or "")
            meta = rec.get("SourceMetadata")
            fs = meta.get("Data", {}).get("Filesystem", {}) \
                if isinstance(meta, dict) else {}
            source_file = str(fs.get("file") or ctx.target)
            preview = raw[:12]
            value = f"secret:{detector}:{source_file}:{preview}"
            if value in seen:
                continue
            seen.add(value)
            severity = ("critical"
                        if detector in ("PrivateKey", "AWS") else "high")
            findings.append({
                "type": "secret",
                "id": f"trufflehog-{detector}",
                "detector": detector,
                "value": value,
                "severity": severity,
                "matched_at": source_file,
                "verified": bool(rec.get("Verified")),
                "redacted_preview": preview,
            })
        return findings





