"""Execution Engine / Resiliency Controller.

``ToolRunner`` executes a native Kali binary via ``asyncio.create_subprocess_exec``
with strict timeout enforcement and bounded retries. Raw STDOUT/STDERR are
always preserved on disk (100% raw-log retention), even when every attempt fails.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass
from typing import Any

from .config import ScanConfig
from .parsers import parse_findings
from .tools import ToolSpec

logger = logging.getLogger("orchestrator.runner")

# Hard cap on retained in-memory output per stream (protects against tools
# that never stop writing).
MAX_STREAM_BYTES = 256 * 1024 * 1024


class DiskFullError(IOError):
    """Raised when log/report writing fails due to disk pressure."""


def write_text_file(path: str, content: str) -> None:
    """Write *content* to *path*, converting OS write errors to DiskFullError."""
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(content)
    except OSError as exc:  # includes ENOSPC (disk full), EACCES, ...
        raise DiskFullError(f"Failed writing {path}: {exc}") from exc


@dataclass
class ToolResult:
    """Unified Vulnerability Schema result for one tool run."""

    target: str
    tool_name: str
    execution_time_sec: float
    status: str  # "success" | "failed" | "skipped"
    findings: list[dict]
    raw_log_reference: str
    retries_used: int = 0
    return_code: int | None = None
    error_summary: str = ""
    started_at: float = 0.0
    ended_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        fmt = lambda ts: (time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ts)) if ts else None)  # noqa: E731
        d = self.__dict__.copy()
        d["started_at"] = fmt(self.started_at)
        d["ended_at"] = fmt(self.ended_at)
        return d


class ToolRunner:
    """Runs a single tool with timeout enforcement and retry logic."""

    def __init__(self, spec: ToolSpec, config: ScanConfig, log_dir: str, ui=None):
        self.spec = spec
        self.config = config
        self.log_dir = log_dir
        self.ui = ui  # optional rich-based status callback object

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    async def run(self, ctx: dict[str, Any]) -> ToolResult:
        """Execute the tool with retries; always preserve raw output."""
        started = time.time()
        raw_path = self._raw_log_path(started)
        attempts_log: list[str] = []
        final_rc: int | None = None
        last_error = ""

        for attempt in range(1, self.config.max_retries + 1):
            header = (
                f"\n{'=' * 70}\n"
                f"[attempt {attempt}/{self.config.max_retries}] {self._arg_preview(ctx)}\n"
                f"started: {time.strftime('%Y-%m-%d %H:%M:%S')}\n{'=' * 70}\n"
            )
            rc, stdout, stderr, error = await self._execute_once(ctx)
            final_rc = rc if rc is not None else final_rc
            attempts_log.append(header + "--- STDOUT ---\n" + stdout
                                + "\n--- STDERR ---\n" + (stderr or ""))
            if error:
                last_error = error
                attempts_log.append(f"\n--- ERROR ---\n{error}\n")

            if rc == 0:
                break

            last_error = last_error or f"exit code {rc}"
            logger.warning(
                "tool=%s attempt=%d/%d failed (rc=%s): %s",
                self.spec.name, attempt, self.config.max_retries, rc,
                (stderr.strip() or error)[:300],
            )
            if attempt < self.config.max_retries:
                delay = self.config.retry_delay_sec * attempt  # linear backoff
                if self.ui:
                    self.ui.update_status(
                        self.spec.name,
                        f"retrying in {delay:.0f}s ({attempt}/{self.config.max_retries} failed)",
                    )
                await asyncio.sleep(delay)

        status = "success" if final_rc == 0 else "failed"
        elapsed = time.time() - started

        # ALWAYS persist raw logs (MUST rule: 100% raw retention).
        write_text_file(raw_path, "".join(attempts_log))

        stdout_full = self._extract_last_stdout("".join(attempts_log))
        findings = (
            parse_findings(
                self.spec.parser_name or "", stdout_full, "", self.config.target_domain
            )
            if status == "success"
            else []
        )

        result = ToolResult(
            target=self.config.target_domain,
            tool_name=self.spec.name,
            execution_time_sec=round(elapsed, 3),
            status=status,
            findings=findings,
            raw_log_reference=os.path.abspath(raw_path),
            retries_used=(1 if status == "success" else self.config.max_retries),
            return_code=final_rc,
            error_summary="" if status == "success" else (last_error or "unknown failure"),
            started_at=started,
            ended_at=time.time(),
        )
        logger.info(
            "tool=%s status=%s findings=%d elapsed=%.1fs raw_log=%s",
            self.spec.name, status, len(findings), elapsed, raw_path,
        )
        return result

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    async def _execute_once(self, ctx: dict[str, Any]):
        """Run one subprocess attempt. Returns (rc, stdout, stderr, error_str)."""
        argv = [self.spec.binary] + self._build_args(ctx)
        logger.debug("executing: %s", " ".join(argv))
        stdout_buf: list[bytes] = []
        stderr_buf: list[bytes] = []

        async def drain(stream, sink: list, echo: bool) -> bytes:
            total = 0
            while True:
                chunk = await stream.read(65536)
                if not chunk:
                    break
                if total < MAX_STREAM_BYTES:
                    sink.append(chunk)
                total += len(chunk)
                if echo and chunk.strip():
                    line = chunk.decode(errors="replace").strip().splitlines()[-1]
                    if self.ui:
                        self.ui.echo_line(self.spec.name, line)
            if total > MAX_STREAM_BYTES:
                logger.warning(
                    "tool=%s output exceeded %d bytes; memory copy truncated "
                    "(disk capture of the tail continues)",
                    self.spec.name, MAX_STREAM_BYTES,
                )
            return b"".join(sink[-4096:]) if total > MAX_STREAM_BYTES else b"".join(sink)

        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.DEVNULL,
            )
            out_task = asyncio.create_task(drain(proc.stdout, stdout_buf, self.config.verbosity == "high"))
            err_task = asyncio.create_task(drain(proc.stderr, stderr_buf, False))

            try:
                await asyncio.wait_for(proc.wait(), timeout=self.config.tool_timeout_sec)
            except asyncio.TimeoutError:
                await self._kill(proc)
                return (
                    None,
                    (await out_task).decode(errors="replace"),
                    (await err_task).decode(errors="replace"),
                    f"timeout after {self.config.tool_timeout_sec}s",
                )

            stdout = (await out_task).decode(errors="replace")
            stderr = (await err_task).decode(errors="replace")
            return proc.returncode, stdout, stderr, ""

        except FileNotFoundError:
            return None, "", "", f"binary not found in PATH: {self.spec.binary}"
        except PermissionError as exc:
            return None, "", "", f"permission denied executing {self.spec.binary}: {exc}"
        except OSError as exc:
            return None, "", "", f"OS error launching {self.spec.binary}: {exc}"


    @staticmethod
    async def _kill(proc: asyncio.subprocess.Process) -> None:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        try:
            await proc.wait()
        except Exception:  # noqa: BLE001
            pass

    def _build_args(self, ctx: dict[str, Any]) -> list[str]:
        if self.spec.build_args is None:
            return []
        return [str(a) for a in self.spec.build_args(self.config, ctx)]

    def _arg_preview(self, ctx: dict[str, Any]) -> str:
        try:
            return " ".join([self.spec.binary] + self._build_args(ctx))
        except Exception:  # noqa: BLE001
            return self.spec.binary

    def _raw_log_path(self, started: float) -> str:
        stamp = time.strftime("%Y%m%d_%H%M%S", time.localtime(started))
        return os.path.join(self.log_dir, f"{self.spec.name}_{stamp}.log")

    @staticmethod
    def _extract_last_stdout(combined: str) -> str:
        """Extract the STDOUT section belonging to the last recorded attempt."""
        marker = "--- STDOUT ---"
        idx = combined.rfind(marker)
        if idx < 0:
            return ""
        rest = combined[idx + len(marker):]
        end = rest.find("--- STDERR ---")
        return rest[:end] if end >= 0 else rest

