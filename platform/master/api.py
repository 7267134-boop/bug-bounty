"""Master Node API - the only internet-facing component.

Endpoints:
  POST /api/v1/scans        submit a scan (auth required; scope enforced)
  GET  /api/v1/scans/{id}   scan status + task states
  GET  /api/v1/scans        recent scans (dashboard backing)
  GET  /api/v1/findings     filtered findings (triage backing)
  PATCH /api/v1/findings/{id}/triage   human validate/refute decision
  GET  /api/v1/dashboard    aggregated snapshot for the control UI
  GET  /api/v1/workflows    list available workflow names
  GET  /api/v1/workers      live worker fleet from heartbeats
  GET  /metrics             prometheus-style counters (auth)
  GET  /healthz /readyz     liveness / readiness

Ownership: the master OWNS planning, dispatch gating, scan finalization,
stale-delivery reclamation and heartbeat garbage collection. Workers never
perform master-owned state transitions.
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import pathlib
import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field, field_validator

from common import db as database
from common.config import Settings, load_settings
from common.logging_setup import setup_logging
from common.redis_client import TaskQueue
from common.scope import (
    InvalidTarget,
    evaluate,
    load_entries,
    normalize_target,
)

from .orchestrator import (
    WorkflowError,
    available_workflows,
    load_workflow,
    plan_tasks,
)

log = logging.getLogger("master.api")

STATE = {"settings": None, "pool": None, "queue": None}
BACKGROUND_TASK = None


def get_settings() -> Settings:
    return STATE["settings"]


async def require_token(x_api_token: str = Header(default="")) -> None:
    settings: Settings = get_settings()
    if not x_api_token or not hmac.compare_digest(x_api_token, settings.api_token):
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Token")


# --------------------------------------------------------------------- #
class ScanRequest(BaseModel):
    program: str = Field(min_length=2, max_length=64)
    workflow: str = Field(min_length=2, max_length=64)
    targets: list[str] = Field(min_length=1, max_length=100)
    requested_by: str = Field(min_length=2, max_length=128)

    @field_validator("program", "workflow", "requested_by")
    @classmethod
    def _safe(cls, v: str) -> str:
        if any(ch in v for ch in "\r\n\x00") or not v.strip():
            raise ValueError("illegal characters")
        return v.strip()


from typing import Literal  # noqa: E402


class TriageRequest(BaseModel):
    """Human triage decision (Pillar B of the cost strategy)."""

    decision: Literal["validated", "refuted"]
    note: str = ""
    requested_by: str = Field(min_length=2, max_length=128)

    @field_validator("note", "requested_by")
    @classmethod
    def _safe(cls, v: str) -> str:
        if any(ch in v for ch in "\r\n\x00"):
            raise ValueError("illegal characters")
        return v.strip()


def create_app() -> FastAPI:
    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        settings = load_settings()
        setup_logging("master", settings.log_level)
        STATE["settings"] = settings
        STATE["pool"] = await database.wait_for_db(settings.pg_dsn)
        await database.run_migrations(STATE["pool"])
        STATE["queue"] = TaskQueue(settings.redis_url, settings.stream_key,
                                   settings.consumer_group)
        await STATE["queue"].connect()
        task = _spawn_background_task()
        try:
            yield
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            await STATE["queue"].close()
            await STATE["pool"].close()

    app = FastAPI(title="Bug Bounty Automation Platform - Master",
                  version="0.1.0", docs_url=None, redoc_url=None,
                  lifespan=lifespan)

    # ---------------- health ---------------- #
    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "alive"}

    @app.get("/readyz")
    async def readyz() -> dict:
        db_ok = False
        redis_ok = False
        try:
            db_ok = bool(await STATE["pool"].fetchval("SELECT 1"))
        except Exception:  # noqa: BLE001
            pass
        if STATE["queue"]:
            redis_ok = await STATE["queue"].ping()
        ok = db_ok and redis_ok
        return {"status": "ok" if ok else "degraded",
                "postgres": db_ok, "redis": redis_ok}

    @app.get("/api/v1/workflows", dependencies=[Depends(require_token)])
    async def list_workflows(settings: Settings = Depends(get_settings)) -> dict:
        return {"workflows": available_workflows(settings.workflows_dir)}

    @app.get("/api/v1/scans", dependencies=[Depends(require_token)])
    async def list_scans_route(limit: int = 25) -> dict:
        rows = await database.list_scans(STATE["pool"], limit)
        for r in rows:
            r["created_at"] = str(r.get("created_at"))
        return {"scans": rows}

    @app.get("/api/v1/dashboard", dependencies=[Depends(require_token)])
    async def dashboard() -> dict:
        """Aggregated snapshot powering the control UI (single round-trip).

        Carries everything the live view needs: KPI metrics, recent scans,
        the unvalidated-severity backlog histogram and the audit-event tail
        (reNgine-style ops dashboard without extra client round-trips).
        """
        pool = STATE["pool"]
        return {
            "metrics": await database.metrics_snapshot(pool),
            "scans": [
                {**row, "created_at": str(row.get("created_at"))}
                for row in await database.list_scans(pool, 15)
            ],
            "severity": await database.severity_histogram(pool),
            "events": [
                {**row, "ts": str(row.get("ts"))}
                for row in await database.recent_events(pool, 12)
            ],
        }

    @app.get("/api/v1/workers", dependencies=[Depends(require_token)])
    async def list_workers_route() -> dict:
        """Live worker fleet (heartbeat table; GC prunes rows >10 min old)."""
        workers = await database.list_workers(STATE["pool"])
        for w in workers:
            w["last_seen"] = str(w.get("last_seen"))
            caps = w.get("capabilities")
            w["capabilities"] = list(caps) if isinstance(caps, (list, tuple)) else []
        return {"workers": workers}


    @app.get("/api/v1/findings", dependencies=[Depends(require_token)])
    async def list_findings_route(
        scan_id: str | None = None,
        state: str | None = None,
        severity: str | None = None,
        is_new: bool | None = None,
        limit: int = 50,
    ) -> dict:
        rows = await database.list_findings(
            STATE["pool"], scan_id=scan_id, state=state,
            severity=severity, is_new=is_new, limit=limit,
        )
        for r in rows:
            r["first_seen"] = str(r.get("first_seen"))
        return {"findings": rows}

    @app.patch("/api/v1/findings/{finding_id}/triage",
               dependencies=[Depends(require_token)])
    async def triage_finding_route(finding_id: str,
                                   body: TriageRequest) -> dict:
        """Human-in-the-loop gate (Pillar B): validate or refute a finding.

        Only ``validated`` findings are eligible for AI deep-dive / reporting.
        Every decision lands in the audit trail.
        """
        pool = STATE["pool"]
        row = await database.triage_finding(
            pool, finding_id, body.decision,
            actor=f"human:{body.requested_by}",
        )
        if row is None:
            raise HTTPException(status_code=404, detail="finding not found")
        await database.audit_event(
            pool, actor=body.requested_by, action="finding.triage",
            subject=finding_id, decision="allow",
            details={"decision": body.decision, "note": body.note,
                     "type": row["type"], "value": row["value"]},
        )
        log.info("finding triaged", extra={"finding_id": finding_id,
                                           "decision": body.decision})
        return {"finding": row}

    _static_dir = pathlib.Path(__file__).resolve().parent / "static"

    @app.get("/", include_in_schema=False)
    async def index() -> "HTMLResponse":
        from fastapi.responses import HTMLResponse

        html = (_static_dir / "index.html").read_text(encoding="utf-8")
        return HTMLResponse(content=html)

    @app.get("/metrics", dependencies=[Depends(require_token)])
    async def metrics() -> dict:
        """Prometheus-style snapshot (JSON). Scrape-adapter friendly."""
        snap = await database.metrics_snapshot(STATE["pool"])
        lines = [
            "# TYPE bb_workers_alive gauge", f"bb_workers_alive {snap['workers_alive']}",
            "# TYPE bb_findings_total counter", f"bb_findings_total {snap['findings_total']}",
            "# TYPE bb_findings_new counter", f"bb_findings_new {snap['findings_new']}",
            "# TYPE bb_findings_unvalidated gauge",
            f"bb_findings_unvalidated {snap['findings_unvalidated']}",
        ]
        for status, n in snap["scans"].items():
            lines.append(f'bb_scans{{status="{status}"}} {n}')
        for state, n in snap["tasks"].items():
            lines.append(f'bb_tasks{{state="{state}"}} {n}')
        return {"snapshot": snap, "prometheus": "\n".join(lines) + "\n"}

    # ---------------- scan submission ---------------- #
    @app.post("/api/v1/scans", status_code=201, dependencies=[Depends(require_token)])
    async def submit_scan(req: ScanRequest) -> dict:
        settings: Settings = get_settings()
        pool = STATE["pool"]
        queue: TaskQueue = STATE["queue"]

        program = await database.get_program_by_name(pool, req.program)
        if program is None or not program["enabled"]:
            await database.audit_event(
                pool, actor=req.requested_by, action="scan.reject_unknown_program",
                subject=req.program, decision="deny", details={},
            )
            raise HTTPException(status_code=403, detail=f"unknown program {req.program!r}")

        wf_path = pathlib.Path(settings.workflows_dir) / f"{req.workflow}.yaml"
        try:
            workflow = load_workflow(wf_path)
        except WorkflowError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        entries = load_entries(await database.get_scope_rows(pool, str(program["id"])))

        decisions: list[dict] = []
        allowed_targets: list[str] = []
        for raw_target in req.targets:
            try:
                target = normalize_target(raw_target)
                decision = evaluate(target, entries)
                decisions.append({"target": raw_target, "allowed": decision.allowed,
                                  "reason": decision.reason})
                if decision.allowed:
                    allowed_targets.append(target)
            except InvalidTarget as exc:
                decisions.append({"target": str(raw_target), "allowed": False,
                                  "reason": f"invalid target: {exc}"})

        denied = [d for d in decisions if not d["allowed"]]
        await database.audit_event(
            pool, actor=req.requested_by,
            action="scan.submit" if not denied else "scan.submit_partial_denies",
            subject=req.program, decision="allow" if not denied else "deny",
            details={"workflow": req.workflow, "decisions": decisions},
        )
        if not allowed_targets:
            raise HTTPException(status_code=403,
                                detail={"message": "all targets rejected by scope policy",
                                        "decisions": decisions})

        scan_id = await database.insert_scan(pool, str(program["id"]), req.workflow,
                                             req.requested_by)
        # Batched insert (executemany) - never per-row execute() in a loop.
        await pool.executemany(
            """INSERT INTO scan_targets(scan_id, target, decision, reason)
               VALUES($1::uuid, $2, $3, $4)""",
            [(scan_id, d["target"],
              "allow" if d["allowed"] else "deny", d["reason"])
             for d in decisions],
        )

        tasks = plan_tasks(scan_id, str(program["id"]), workflow, allowed_targets)
        enqueued = 0
        for t in tasks:
            task_id = await database.insert_task(
                pool, scan_id=scan_id, step_name=t["step_name"], tool=t["tool"],
                payload={"target": t["target"], **t["params"]},
                idempotency_key=t["idempotency_key"],
                max_attempts=t["max_attempts"],
                depends_on=t.get("depends_on") or [],
                when_finding_type=t.get("when_finding_type"),
            )
            if task_id is None:
                continue
            if t.get("depends_on"):
                # Dispatcher promotes this once all dependencies succeed.
                continue
            await queue.enqueue(_task_message(task_id, t, program, scan_id))
            await database.mark_dispatched(pool, [task_id])
            enqueued += 1
        await database.update_scan_status(pool, scan_id, "running")
        log.info("scan accepted", extra={"scan_id": scan_id, "tasks": enqueued})
        return {"scan_id": scan_id, "tasks_enqueued": enqueued,
                "targets_allowed": len(allowed_targets), "decisions": decisions}

    @app.get("/api/v1/scans/{scan_id}", dependencies=[Depends(require_token)])
    async def scan_status(scan_id: str) -> dict:
        pool = STATE["pool"]
        row = await pool.fetchrow(
            "SELECT id::text, program_id::text, workflow, status, created_at "
            "FROM scans WHERE id = $1::uuid",   # PK index used (no ::text cast)
            scan_id,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="scan not found")
        states = {
            r["state"]: r["n"] for r in await database.task_states(pool, scan_id)
        }
        return {"scan": dict(row), "task_states": states}

    @app.get("/api/v1/scans/{scan_id}/report",
             dependencies=[Depends(require_token)])
    async def scan_report_route(scan_id: str, format: str = "json") -> object:
        """Stage 6: validated+new findings as a JSON report or Markdown.

        The validated/new filter is applied IN THE DATABASE QUERY
        (Pillar B) — the renderer cannot accidentally leak unvalidated
        findings even if it wanted to.
        """
        from fastapi.responses import PlainTextResponse

        from .reporting import build_report, to_markdown

        fmt = str(format).strip().lower()
        if fmt not in ("json", "md"):
            raise HTTPException(status_code=400,
                                detail="format must be 'json' or 'md'")
        material = await database.report_material(STATE["pool"], scan_id)
        if material is None:
            raise HTTPException(status_code=404, detail="scan not found")
        report = build_report(material)
        if fmt == "md":
            return PlainTextResponse(to_markdown(report),
                                     media_type="text/markdown; charset=utf-8")
        return report

    return app


def _task_message(task_id: str, planned: dict, program: dict, scan_id: str) -> dict:
    """Build the Redis stream payload from a planned-task dict."""
    target = planned["target"]
    return {
        "task_id": task_id,
        "idempotency_key": planned["idempotency_key"],
        "scan_id": scan_id,
        "program_id": str(program["id"]),
        "step_name": planned["step_name"],
        "tool": planned["tool"],
        "target": "" if "," in target else target,
        "params": planned["params"],
        "attempt": 1,
        "max_attempts": planned["max_attempts"],
        "issued_at_epoch": time.time(),
    }


async def _dispatch_ready_tasks(pool, queue) -> int:
    """Promote queued tasks whose dependencies have all succeeded."""
    import json as _json

    ready = await database.ready_tasks(pool)
    if not ready:
        return 0
    dispatched_ids: list[str] = []
    for row in ready:
        payload = row["payload"]
        if not isinstance(payload, dict):
            try:
                payload = _json.loads(payload or "{}")
            except ValueError:
                payload = {}
        target = str(payload.pop("target", ""))
        await queue.enqueue({
            "task_id": row["task_id"],
            "idempotency_key": row["idempotency_key"],
            "scan_id": row["scan_id"],
            "program_id": row["program_id"],
            "step_name": row["step_name"],
            "tool": row["tool"],
            "target": "" if "," in target else target,
            "params": payload,
            "attempt": 1,
            "max_attempts": int(row["max_attempts"]),
            "issued_at_epoch": time.time(),
        })
        dispatched_ids.append(row["task_id"])
    await database.mark_dispatched(pool, dispatched_ids)
    log.info("dependency-ready tasks dispatched", extra={"count": len(dispatched_ids)})
    return len(dispatched_ids)


async def _background_loop() -> None:
    """Single master-owned maintenance loop.

    Responsibilities (clear ownership, no worker overlap):
      * reclaim stale task deliveries (crashed workers)
      * promote dependency/routing-gated tasks
      * finalize completed scans + heartbeat GC
    """
    settings: Settings = get_settings()
    queue: TaskQueue = STATE["queue"]
    pool = STATE["pool"]

    while True:
        try:
            await queue.reclaim_stale(settings.stale_requeue_secs * 1000)
            await _dispatch_ready_tasks(pool, queue)
            # Heartbeat GC is MASTER-owned; workers only insert their own row.
            await pool.execute(
                "DELETE FROM worker_heartbeats "
                "WHERE last_seen < now() - interval '10 minutes'"
            )
            await _finalize_scans(pool)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.warning("background loop error", extra={"error": str(exc)})
        await asyncio.sleep(30)


def _spawn_background_task():
    """Spawn the maintenance loop from a running event loop."""
    return asyncio.create_task(_background_loop(), name="master-background")


async def _finalize_scans(pool) -> None:
    """Close scans whose task set is fully terminal.

    State-machine mapping: dependency-waiting tasks are state='queued' with
    dispatched=FALSE, so they correctly keep the scan open. Failed/dead steps
    cascade-abort their dependents (worker side, see db.abort_dependents),
    so a scan can never hang waiting on a doomed branch.
    """
    rows = await pool.fetch("""
        SELECT s.id::text AS scan_id
          FROM scans s
         WHERE s.status = 'running'
           AND NOT EXISTS (
               SELECT 1 FROM tasks t
                WHERE t.scan_id = s.id AND t.state IN ('queued','running'))
    """)
    for row in rows:
        counts = {r["state"]: r["n"] for r in await database.task_states(pool, row["scan_id"])}
        succeeded = counts.get("succeeded", 0)
        failed = sum(counts.get(s, 0) for s in ("failed", "aborted", "dead"))
        if succeeded or failed:
            new_status = "completed" if succeeded else "failed"
            await database.update_scan_status(pool, row["scan_id"], new_status)
            await database.audit_event(
                pool, actor="master", action="scan.finalized",
                subject=row["scan_id"], decision="info",
                details={"status": new_status, "states": counts},
            )
            from common.notifications import notify_event

            await notify_event(
                "scan.finalized",
                details={"scan_id": row["scan_id"], "status": new_status,
                         "task_states": counts},
                text=f"Scan {row['scan_id'][:8]}… {new_status}",
            )


app = create_app()
