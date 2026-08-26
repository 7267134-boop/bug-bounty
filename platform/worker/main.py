"""Restricted Worker Node - Stage 1.

Consume loop:
  XREADGROUP -> parse TaskMessage -> RE-CHECK SCOPE (defense in depth)
  -> capability gate -> sandboxed execution -> persist result in PG
  -> retry or dead-letter -> XACK.

The worker has NO inbound ports. It is reachable only via Redis and
PostgreSQL on the internal docker network.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import tempfile

from common import db as database
from common.config import load_settings
from common.events import TaskMessage, TaskResult
from common.logging_setup import setup_logging
from common.ratelimit import TokenBucket
from common.redis_client import TaskQueue, new_consumer_name
from common.scope import (
    InvalidTarget,
    OutOfScopeError,
    ScopeEntry,
    assert_in_scope,
    load_entries,
)

from .executor import Executor
from .tools.base import ToolContext, ToolExecutionError, ToolNotPermitted
from .tools.registry import known_tools, resolve_tool

log = logging.getLogger("worker")


class Worker:
    def __init__(self) -> None:
        self.settings = load_settings()
        self.capabilities = [
            c.strip() for c in os.environ.get("WORKER_CAPABILITIES", "").split(",") if c.strip()
        ]
        if not self.capabilities:
            raise RuntimeError("WORKER_CAPABILITIES is empty - refusing to start (fail closed)")
        unknown = [c for c in self.capabilities if c not in known_tools()]
        if unknown:
            raise RuntimeError(f"capabilities reference unregistered tools: {unknown}")
        self.worker_id = self.settings.consumer_name
        self.consumer = new_consumer_name(self.worker_id)
        self.rate_bucket = TokenBucket(rate=self.settings.worker_rate_rps)
        self.queue = TaskQueue(
            self.settings.redis_url, self.settings.stream_key, self.settings.consumer_group
        )
        self.executor = Executor(self.settings.max_output_bytes,
                                 extra_env_keys=self.settings.extra_env_keys)
        self.pool = None
        self._stopping = asyncio.Event()

    # ------------------------------------------------------------------ #
    async def start(self) -> None:
        setup_logging("worker", self.settings.log_level)
        log.info("worker starting", extra={
            "worker_id": self.worker_id, "consumer": self.consumer,
            "capabilities": self.capabilities,
        })
        self.pool = await database.wait_for_db(self.settings.pg_dsn)
        await self.queue.connect()
        await database.run_migrations(self.pool)   # no-op when master already applied

        hb = asyncio.create_task(self._heartbeat_loop())
        reclaimer = asyncio.create_task(self._reclaim_loop())
        loop = asyncio.create_task(self._consume_loop())
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                asyncio.get_running_loop().add_signal_handler(sig, self._stopping.set)
            except NotImplementedError:      # Windows dev box
                pass
        await self._stopping.wait()

        for task in (loop, hb, reclaimer):
            task.cancel()
        await self.queue.close()
        await self.pool.close()
        log.info("worker stopped cleanly")

    async def _heartbeat_loop(self) -> None:
        while True:
            try:
                # Insert/update OWN row only; GC of stale workers is
                # master-owned (single-writer principle).
                await database.heartbeat(self.pool, self.worker_id,
                                         self.capabilities)
            except Exception as exc:  # noqa: BLE001
                log.warning("heartbeat failed", extra={"error": str(exc)})
            await asyncio.sleep(15)

    async def _reclaim_loop(self) -> None:
        while True:
            try:
                n = await self.queue.reclaim_stale(self.settings.stale_requeue_secs * 1000)
                if n:
                    log.info("reclaimed stale deliveries", extra={"count": n})
            except Exception as exc:  # noqa: BLE001
                log.warning("reclaim failed", extra={"error": str(exc)})
            await asyncio.sleep(60)

    async def _consume_loop(self) -> None:
        sem = asyncio.Semaphore(max(1, self.settings.worker_concurrency))
        # Bounded exponential backoff on consume errors: transient Redis
        # outages retry gently, and a *persistent* error (bad deploy,
        # programming bug) can never hot-spin the CPU or flood the logs.
        # TUNABLE(final-tuning-pending): base/max backoff seconds below --
        # see docs/TUNING.md (consume_error_backoff_*).
        backoff_secs = getattr(self.settings, "consume_error_backoff_secs", 3.0)
        backoff_max = getattr(self.settings, "consume_error_backoff_max_secs", 30.0)
        failures = 0
        while not self._stopping.is_set():
            try:
                messages = await self.queue.consume(
                    self.consumer, count=1, block_ms=self.settings.block_secs * 1000
                )
            except Exception as exc:  # noqa: BLE001
                failures += 1
                delay = min(backoff_max, backoff_secs * 2 ** (failures - 1))
                log.error("consume error; backing off",
                          extra={"error": str(exc), "failure_streak": failures,
                                 "delay_secs": delay})
                await asyncio.sleep(delay)
                continue
            failures = 0                      # success resets the backoff window
            for entry_id, payload in messages or []:
                await sem.acquire()
                asyncio.create_task(self._process(entry_id, payload, sem))

    async def _process(self, entry_id: str, payload: dict, sem: asyncio.Semaphore) -> None:
        try:
            await self._handle(entry_id, payload)
        except Exception as exc:  # noqa: BLE001 - a task must never kill the worker
            log.exception("unhandled task failure", extra={"entry_id": entry_id})
            try:
                await database.audit_event(
                    self.pool, actor=f"worker:{self.worker_id}",
                    action="task.internal_error", subject=payload.get("task_id", "?"),
                    decision="error", details={"error": str(exc)},
                )
            except Exception:  # noqa: BLE001
                pass
        finally:
            sem.release()

    async def _handle(self, entry_id: str, payload: dict) -> None:
        msg = TaskMessage.model_validate(payload)

        claimed = await self.pool.fetchrow(
            """UPDATE tasks SET state='running', claimed_by=$2, claimed_at=now()
               WHERE id = $1::uuid AND state IN ('queued','running')
               RETURNING max_attempts""",
            msg.task_id, f"worker:{self.worker_id}",
        )
        if claimed is None:
            log.warning("task not claimable (terminal already?) - acking",
                        extra={"task_id": msg.task_id})
            await self.queue.ack(entry_id)
            return
        max_attempts = int(claimed["max_attempts"])

        # ---- Gate 1: scope enforcement (worker-side, defense in depth) ----
        rows = await database.get_scope_rows(self.pool, msg.program_id)
        entries: list[ScopeEntry] = load_entries(rows)
        # 'once' steps carry the full target list in params; otherwise the
        # single task target is validated.
        targets_to_check = msg.params.get("targets") or ([msg.target] if msg.target else [])
        try:
            if not targets_to_check:
                raise OutOfScopeError("task carries no validatable target")
            for candidate in targets_to_check:
                assert_in_scope(str(candidate), entries)
        except (OutOfScopeError, InvalidTarget) as exc:
            log.error("OUT OF SCOPE - task refused", extra={
                "task_id": msg.task_id, "target": msg.target, "reason": str(exc),
            })
            await self._finalize(msg, TaskResult(
                task_id=msg.task_id, ok=False, summary="out of scope",
                error=str(exc), exit_code=None,
            ), state="failed")
            # Scope denial is terminal for the whole branch: nothing downstream
            # may run for this target.
            await database.abort_dependents(self.pool, msg.scan_id, msg.step_name)
            await database.audit_event(
                self.pool, actor=f"worker:{self.worker_id}", action="task.scope_deny",
                subject=msg.task_id, decision="deny",
                details={"target": msg.target, "tool": msg.tool},
            )
            await self.queue.ack(entry_id)
            return

        # ---- Gate 2: capability allowlist ----
        try:
            tool = resolve_tool(msg.tool, self.capabilities)
        except ToolNotPermitted as exc:
            log.error("capability gate refusal", extra={
                "task_id": msg.task_id, "tool": msg.tool,
            })
            await self._finalize(msg, TaskResult(
                task_id=msg.task_id, ok=False, summary="tool not permitted",
                error=str(exc), exit_code=None,
            ), state="dead")
            await self.queue.ack(entry_id)
            return

        # ---- Execute inside the sandbox (rate-limited) ----
        workdir = tempfile.mkdtemp(prefix=f"task-{msg.task_id[:8]}-")
        ctx = await self._build_context(tool, msg, workdir)
        try:
            if tool.batch_mode:
                argv_list = tool.build_argv_batch(ctx)
            else:
                argv = tool.build_argv(ctx)
        except ToolExecutionError as exc:
            # Non-retryable configuration/parameter error -> dead-letter now;
            # downstream steps of a doomed branch must be aborted as well.
            await self._finalize(msg, TaskResult(
                task_id=msg.task_id, ok=False, summary="invalid tool parameters",
                error=str(exc), exit_code=None,
            ), state="dead")
            await database.abort_dependents(self.pool, msg.scan_id, msg.step_name)
            await self.queue.ack(entry_id)
            return
        stdin_bytes = None if tool.batch_mode or tool.needs_input_file \
            else tool.stdin_data(ctx)
        await self.rate_bucket.acquire()   # politeness: program RPS ceiling
        if tool.batch_mode:
            result = self.executor.run_batch(argv_list, ctx)
        else:
            result = self.executor.run(argv, ctx, stdin_bytes=stdin_bytes)

        if result.ok:
            findings = tool.parse(result, ctx)
            recorded, new_count = await database.record_findings(
                self.pool, program_id=msg.program_id, scan_id=msg.scan_id,
                task_id=msg.task_id, target=msg.target, findings=findings,
            )
            await self._finalize(msg, TaskResult(
                task_id=msg.task_id, ok=True, exit_code=result.return_code,
                duration_ms=result.duration_ms,
                summary=f"{len(findings)} finding(s) "
                        f"({recorded} stored, {new_count} new)",
                findings_count=len(findings),
            ), state="succeeded", findings=findings)
            await database.audit_event(
                self.pool, actor=f"worker:{self.worker_id}", action="task.completed",
                subject=msg.task_id, decision="allow",
                details={"tool": msg.tool, "findings": len(findings),
                         "new_findings": new_count},
            )
            await self.queue.ack(entry_id)
            return

        # ---- Failure path: bounded retry with backoff, then dead-letter ----
        attempt = int(payload.get("attempt", 1))
        if attempt < max_attempts:
            delay = min(30, 2 ** attempt)
            log.warning("task failed; retrying", extra={
                "task_id": msg.task_id, "attempt": attempt,
                "delay_s": delay, "rc": result.return_code,
            })
            await self.pool.execute(
                "UPDATE tasks SET state='queued', error=$2 WHERE id = $1::uuid",
                msg.task_id, (result.stderr or "")[:2000],
            )
            payload["attempt"] = attempt + 1
            await asyncio.sleep(delay)
            await self.queue.enqueue(payload)     # redelivery carries attempt+1
            await self.queue.ack(entry_id)        # old delivery is done with
            return

        log.error("task dead-lettered", extra={
            "task_id": msg.task_id, "attempt": attempt,
        })
        await self._finalize(msg, TaskResult(
            task_id=msg.task_id, ok=False, exit_code=result.return_code,
            duration_ms=result.duration_ms, summary="exhausted retries",
            error=(result.stderr or "")[:2000],
        ), state="dead")
        # Terminal failure: cascade-abort every queued dependent step so the
        # scan can finalize instead of hanging forever.
        await database.abort_dependents(self.pool, msg.scan_id, msg.step_name)
        await database.audit_event(
            self.pool, actor=f"worker:{self.worker_id}", action="task.dead_letter",
            subject=msg.task_id, decision="error",
            details={"tool": msg.tool, "rc": result.return_code},
        )
        await self.queue.ack(entry_id)

    async def _finalize(self, msg: TaskMessage, result: TaskResult,
                        state: str, findings: list[dict] | None = None) -> None:
        """Persist the terminal task outcome in PostgreSQL."""
        import json

        await self.pool.execute(
            """UPDATE tasks
                  SET state=$2, finished_at=now(),
                      result=$3::jsonb, error=$4
                WHERE id = $1::uuid""",
            msg.task_id, state,
            json.dumps({
                "ok": result.ok, "exit_code": result.exit_code,
                "duration_ms": result.duration_ms, "summary": result.summary,
                "findings_count": result.findings_count,
                "findings": findings or [],
            }, separators=(",", ":"), default=str),
            result.error,
        )


    async def _build_context(self, tool, msg: TaskMessage, workdir: str) -> ToolContext:
        """Assemble ToolContext incl. upstream findings materialization.

        Raises ToolExecutionError when a file-consuming tool has no upstream
        data - a fast, non-retryable dead-letter instead of a wasted run.
        """
        inputs = await database.scan_finding_values(self.pool, msg.scan_id,
                                                    tool.consumes)
        input_file = None
        if tool.needs_input_file:
            values: list[str] = []
            seen: set[str] = set()
            for ftype in tool.consumes:
                for value in inputs.get(ftype, []):
                    if value not in seen:
                        seen.add(value)
                        values.append(value)
            values = values[:100_000]            # hard cap for safety
            if not values:
                raise ToolExecutionError(
                    f"no upstream findings of type {tool.consumes} "
                    f"for scan {msg.scan_id}"
                )
            input_file = os.path.join(workdir, "input.txt")
            with open(input_file, "w", encoding="utf-8") as fh:
                fh.write("\n".join(values))
        s = self.settings
        return ToolContext(
            task_id=msg.task_id, scan_id=msg.scan_id, program_id=msg.program_id,
            step_name=msg.step_name, target=msg.target, params=dict(msg.params),
            attempt=msg.attempt, timeout_secs=s.task_timeout_secs,
            max_output_bytes=s.max_output_bytes, workdir=workdir,
            rate_limit_rps=float(getattr(tool, "rate_limit_rps", 10.0)),
            inputs=inputs, input_file=input_file,
        )

async def main() -> None:  # pragma: no cover
    await Worker().start()


if __name__ == "__main__":
    asyncio.run(main())

