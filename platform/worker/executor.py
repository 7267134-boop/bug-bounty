"""Sandboxed subprocess execution for worker tools.

Hardening applied to every spawned process:

* argv-list only, ``shell=False`` - no shell interpretation, ever.
* minimal environment (PATH/HOME/LANG only; secrets are never inherited).
* POSIX rlimits: CPU seconds, address space, file size, open files.
* wall-clock timeout -> SIGKILL of the whole process group.
* stdout/stderr captured with a hard byte cap.
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import time

from .tools.base import ExecResult, ToolContext

log = logging.getLogger("worker.executor")

# Environment variables forwarded into tool processes.
_ENV_ALLOWLIST = ["PATH", "LANG", "LC_ALL", "TMPDIR", "HOME", "SSL_CERT_FILE"]


def _make_preexec(ctx: ToolContext):
    """Build the child-side rlimit/session setup closure (Linux only)."""
    import resource

    def _apply():  # pragma: no cover - runs in child on Linux
        cpu_secs = max(1, ctx.timeout_secs)
        mem_bytes = 2 * 1024 * 1024 * 1024          # 2 GiB address space cap
        fsize = max(1_048_576, ctx.max_output_bytes * 4)
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_secs, cpu_secs))
        resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
        resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
        # New session => we can kill the whole process group on timeout.
        os.setsid()

    return _apply


def _kill_process_group(proc: subprocess.Popen) -> None:  # pragma: no cover
    # POSIX: kill the whole session (children included). Windows dev boxes:
    # terminate the direct child only.
    if os.name == "posix":
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            return
        except (ProcessLookupError, PermissionError):
            pass
    try:
        proc.kill()
    except ProcessLookupError:
        pass


def _build_environment(extra_env_keys: set[str], home: str) -> dict:
    """Minimal, explicitly-allowed environment for tool processes.

    Two layers:
      1. BASE allowlist of harmless runtime vars; anything whose *name*
         smells like a credential is dropped from this layer by default.
      2. OPT-IN passthrough (``WORKER_ENV_PASSTHROUGH`` -> ``extra_env_keys``):
         operator-declared provider keys (e.g. SHODAN_API_KEY) are forwarded
         verbatim and intentionally OVERRIDE the naive name filter — that is
         the whole point: explicit authorization beats string guessing.
    Nothing else from the worker's environment ever reaches a tool.
    """
    _CREDENTIALISH = ("secret", "token", "password")

    def base_allowed(name: str) -> bool:
        lowered = name.lower()
        return not (lowered.endswith("key")
                    or any(marker in lowered for marker in _CREDENTIALISH))

    env = {k: os.environ[k] for k in _ENV_ALLOWLIST
           if k in os.environ and base_allowed(k)}
    for name in extra_env_keys:
        value = os.environ.get(name)
        if value:                                   # explicit opt-in; empties skipped
            env[name] = value
    env.setdefault("HOME", home)
    return env


class Executor:
    """Runs one tool invocation inside the sandbox described above."""

    def __init__(self, max_output_bytes: int = 1_000_000,
                 extra_env_keys: list[str] | None = None):
        self.max_output_bytes = max_output_bytes
        # Explicitly whitelisted env vars forwarded to tools (API keys etc.).
        self.extra_env_keys = set(extra_env_keys or [])

    def run(self, argv: list[str], ctx: ToolContext,
            stdin_bytes: bytes | None = None) -> ExecResult:
        started = time.monotonic()
        env = _build_environment(self.extra_env_keys, ctx.workdir)
        log.info("exec start", extra={"tool_step": ctx.step_name, "argv0": argv[0],
                                      "task_id": ctx.task_id, "attempt": ctx.attempt})
        try:
            proc = subprocess.Popen(
                argv,
                shell=False,                       # NEVER a shell
                cwd=ctx.workdir,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
                preexec_fn=_make_preexec(ctx) if os.name == "posix" else None,
            )
        except FileNotFoundError:
            return ExecResult(None, "", f"binary not found: {argv[0]}",
                              int((time.monotonic() - started) * 1000))
        except PermissionError as exc:
            return ExecResult(None, "", f"permission denied: {exc}",
                              int((time.monotonic() - started) * 1000))

        timed_out = False
        try:
            out, err = proc.communicate(input=stdin_bytes, timeout=ctx.timeout_secs)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_process_group(proc)
            out, err = proc.communicate()

        duration_ms = int((time.monotonic() - started) * 1000)
        stdout = self._cap(out or b"").decode(errors="replace")
        stderr = self._cap(err or b"").decode(errors="replace")
        if timed_out:
            stderr += f"\n[executor] killed after {ctx.timeout_secs}s timeout"
        log.info("exec done", extra={"tool_step": ctx.step_name, "rc": proc.returncode,
                                     "duration_ms": duration_ms, "timed_out": timed_out})
        return ExecResult(proc.returncode, stdout, stderr, duration_ms, timed_out)

    def _cap(self, data: bytes) -> bytes:
        return data[: self.max_output_bytes]

    def run_batch(self, argv_list: list[list[str]], ctx: ToolContext) -> ExecResult:
        """Run several argvs sequentially; merge into one ExecResult.

        Used by batch_mode wrappers (one target per process). Every batch
        member runs to completion — partial evidence is preserved even when
        a later member fails.
        """
        started = time.monotonic()
        outs: list[str] = []
        errs: list[str] = []
        codes: list[int | None] = []
        any_timed_out = False
        for i, argv in enumerate(argv_list):
            r = self.run(argv, ctx)
            codes.append(r.return_code)
            any_timed_out = any_timed_out or r.timed_out
            header = f"### batch[{i}] argv0={argv[0]} rc={r.return_code}"
            outs.append(f"{header}\n{r.stdout}")
            if r.stderr.strip():
                errs.append(f"{header}\n{r.stderr}")
        merged_rc: int | None = 0
        for c in codes:
            if c not in (0, None):
                merged_rc = c
                break
        duration_ms = int((time.monotonic() - started) * 1000)
        return ExecResult(
            merged_rc,
            "\n".join(outs),
            "\n".join(errs),
            duration_ms,
            any_timed_out,
        )
