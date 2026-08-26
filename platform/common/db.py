"""PostgreSQL access: connection pool, migrations, and typed helpers."""

from __future__ import annotations

import logging
import pathlib
from typing import Any, Sequence

import asyncpg

log = logging.getLogger("common.db")

MIGRATIONS_DIR = pathlib.Path(__file__).resolve().parent.parent / "migrations"


async def connect(dsn: str, min_size: int = 1, max_size: int = 5) -> asyncpg.Pool:
    pool = await asyncpg.create_pool(
        dsn=dsn, min_size=min_size, max_size=max_size,
        command_timeout=30, timeout=15,
    )
    return pool


async def run_migrations(pool: asyncpg.Pool, migrations_dir: pathlib.Path | None = None) -> int:
    """Apply .sql migrations in filename order exactly once (crash-safe)."""
    directory = migrations_dir or MIGRATIONS_DIR
    await pool.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            name TEXT PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    applied = {
        row["name"] for row in await pool.fetch("SELECT name FROM schema_migrations")
    }
    files = sorted(p for p in directory.glob("*.sql")) if directory.exists() else []
    count = 0
    for path in files:
        if path.name in applied:
            continue
        sql = path.read_text(encoding="utf-8")
        async with pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(sql)
                await conn.execute(
                    "INSERT INTO schema_migrations(name) VALUES($1)", path.name
                )
        log.info("migration applied", extra={"migration": path.name})
        count += 1
    return count


# --------------------------------------------------------------------- #
# Typed query helpers used by master and worker.
# --------------------------------------------------------------------- #
async def get_program_by_name(pool: asyncpg.Pool, name: str) -> Any | None:
    return await pool.fetchrow("SELECT * FROM programs WHERE name = $1", name)


async def get_scope_rows(pool: asyncpg.Pool, program_id: str) -> list[tuple[str, bool]]:
    rows = await pool.fetch(
        "SELECT pattern, is_allowed FROM scope_entries WHERE program_id = $1",
        program_id,
    )
    return [(r["pattern"], r["is_allowed"]) for r in rows]


async def insert_scan(pool: asyncpg.Pool, program_id: str, workflow: str,
                      requested_by: str) -> str:
    scan_id = await pool.fetchval(
        """INSERT INTO scans(program_id, workflow, requested_by)
           VALUES($1, $2, $3) RETURNING id""",
        program_id, workflow, requested_by,
    )
    return str(scan_id)


async def insert_task(pool: asyncpg.Pool, *, scan_id: str, step_name: str, tool: str,
                      payload: dict, idempotency_key: str, max_attempts: int,
                      depends_on: list[str] | None = None,
                      when_finding_type: str | None = None) -> str | None:
    """Insert a task; returns None when the idempotency key already exists.

    Re-planning after a crash therefore cannot create duplicate executions.
    Tasks with dependencies start as queued+undispatched; the master's
    dispatcher promotes them once every dependency has succeeded AND the
    optional ``when_finding_type`` routing gate is satisfied.
    """
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO tasks(scan_id, step_name, tool, payload, idempotency_key,
                              max_attempts, depends_on, when_finding_type)
            VALUES($1::uuid, $2, $3, $4::jsonb, $5, $6, $7, $8)
            ON CONFLICT (idempotency_key) DO NOTHING
            RETURNING id::text
            """,
            scan_id, step_name, tool, _json(payload), idempotency_key,
            max_attempts, list(depends_on or []), when_finding_type,
        )
        if row:
            return row["id"]
        log.info("duplicate plan suppressed by idempotency key",
                 extra={"idempotency_key": idempotency_key})
        existing = await conn.fetchval(
            "SELECT id::text FROM tasks WHERE idempotency_key=$1", idempotency_key
        )
        return existing or None


# --------------------------------------------------------------------- #
# Dependency-aware dispatch (promote tasks whose deps all succeeded).
# --------------------------------------------------------------------- #
_READY_TASKS_SQL = """
SELECT t.id::text AS task_id, t.idempotency_key, t.scan_id::text AS scan_id,
       s.program_id::text AS program_id, t.step_name, t.tool, t.payload,
       t.max_attempts
  FROM tasks t
  JOIN scans s ON s.id = t.scan_id
 WHERE t.dispatched = FALSE AND t.state = 'queued'
   AND NOT EXISTS (
       SELECT 1
         FROM unnest(t.depends_on) AS d(step)
         JOIN tasks dep ON dep.scan_id = t.scan_id AND dep.step_name = d.step
        WHERE dep.state <> 'succeeded')
   AND (
        t.when_finding_type IS NULL
        OR EXISTS (SELECT 1 FROM findings f
                    WHERE f.scan_id = t.scan_id
                      AND f.type = t.when_finding_type)
   )
 LIMIT 50
"""


async def scan_finding_values(pool: asyncpg.Pool, scan_id: str,
                              types: list[str]) -> dict[str, list[str]]:
    """Distinct finding values per type for one scan (inter-tool data flow)."""
    if not types:
        return {}
    rows = await pool.fetch(
        """SELECT type, value FROM findings
            WHERE scan_id=$1::uuid AND type = ANY($2)
            ORDER BY id ASC""",
        scan_id, list(types),
    )
    grouped: dict[str, list[str]] = {t: [] for t in types}
    for row in rows:
        bucket = grouped.setdefault(row["type"], [])
        if row["value"] not in bucket:
            bucket.append(row["value"])
    return grouped


async def ready_tasks(pool: asyncpg.Pool) -> list[dict]:
    """Queued, undispatched tasks whose dependencies are all satisfied.

    Algorithmic-routing gate: tasks declaring ``when_finding_type`` are held
    back until the scan has produced at least one finding of that type -
    expensive tools only run when cheaper recon actually justifies them.
    """
    rows = await pool.fetch(_READY_TASKS_SQL)
    return [dict(r) for r in rows]


async def mark_dispatched(pool: asyncpg.Pool, task_ids: list[str]) -> None:
    if not task_ids:
        return
    # UUID equality (never id::text) so the primary-key index is used.
    await pool.execute(
        "UPDATE tasks SET dispatched = TRUE WHERE id = ANY($1::uuid[])", task_ids
    )


async def abort_dependents(pool: asyncpg.Pool, scan_id: str,
                           failed_step: str) -> int:
    """Abort every queued task transitively depending on a failed step.

    Recursive CTE walks the reverse dependency edges within the scan; the
    workflow DAG is acyclic (validated at plan time), so recursion terminates.
    Prevents scans from hanging forever when an upstream step fails.
    """
    result = await pool.fetchval(
        """
        WITH RECURSIVE bad(step_name) AS (
            SELECT $2::text
          UNION
            SELECT t.step_name
              FROM tasks t
              JOIN bad b ON t.depends_on @> ARRAY[b.step_name]
             WHERE t.scan_id = $1::uuid
        )
        UPDATE tasks
           SET state = 'aborted',
               error = 'upstream dependency failed or was aborted',
               finished_at = now()
         WHERE scan_id = $1::uuid
           AND state = 'queued'
           AND step_name IN (SELECT step_name FROM bad)
         RETURNING 1
        """,
        scan_id, failed_step,
    )
    return int(result or 0)


# --------------------------------------------------------------------- #
# Findings store: normalized entities w/ cross-scan dedup (state diffing).
# --------------------------------------------------------------------- #
from .constants import FINDING_VALUE_KEYS, SEVERITIES  # noqa: E402


def _finding_identity(program_id: str, finding: dict) -> tuple[str, str] | None:
    from .ids import entity_fingerprint

    ftype = str(finding.get("type") or "unknown").strip().lower()
    value = _VALUE_KEY_VALUE(finding)
    if not value:
        return None
    return ftype, entity_fingerprint(program_id, ftype, value)


def _VALUE_KEY_VALUE(finding: dict) -> str:
    for key in FINDING_VALUE_KEYS:
        v = finding.get(key)
        if isinstance(v, (int, float)):
            return str(v)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


async def record_findings(pool: asyncpg.Pool, *, program_id: str, scan_id: str,
                          task_id: str | None, target: str,
                          findings: list[dict]) -> tuple[int, int]:
    """Persist parsed findings; flags cross-scan NEW entities.

    Performance: one connection acquisition and one set-membership query per
    batch (not per finding); inserts run inside a single transaction.
    Returns (recorded, new_count). Malformed findings are skipped, never fatal.
    """
    if not findings:
        return 0, 0

    identities: list[tuple[str, str, dict]] = []
    for finding in findings:
        identity = _finding_identity(program_id, finding)
        if identity is not None:
            identities.append((identity[0], identity[1], finding))
    if not identities:
        return 0, 0

    fingerprints = [fp for _, fp, _ in identities]
    recorded = new_count = 0
    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                rows = await conn.fetch(
                    """SELECT fingerprint FROM findings
                        WHERE program_id=$1::uuid
                          AND fingerprint = ANY($2)""",
                    program_id, fingerprints,
                )
                seen_before = {r["fingerprint"] for r in rows}
                # In-batch dedup: keep the first occurrence of each fingerprint
                # (duplicates are collapsed; DB conflict-guard remains as safety).
                unique: dict[str, tuple[str, str, dict]] = {}
                for ftype, fingerprint, finding in identities:
                    unique.setdefault(fingerprint, (ftype, fingerprint, finding))
                records = []
                for ftype, fingerprint, finding in unique.values():
                    severity = finding.get("severity")
                    confidence = finding.get("cvss_score") or finding.get("confidence")
                    records.append((
                        program_id, scan_id, task_id, target or "", ftype,
                        _VALUE_KEY_VALUE(finding),
                        severity if severity in SEVERITIES else None,
                        fingerprint, fingerprint not in seen_before,
                        confidence, _json(finding),
                    ))
                await conn.executemany(
                    """
                    INSERT INTO findings(program_id, scan_id, task_id, target, type,
                                         value, severity, fingerprint, is_new,
                                         confidence, metadata)
                    VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)
                    ON CONFLICT (program_id, fingerprint, scan_id)
                    DO UPDATE SET last_seen = now()
                    """,
                    records,
                )
            recorded = len(records)
            new_count = sum(1 for r in records if r[8])
    except Exception as exc:  # noqa: BLE001 - persistence must not kill a task
        log.warning("findings batch persistence failed", extra={"error": str(exc)})
    return recorded, new_count


async def list_scans(pool: asyncpg.Pool, limit: int = 25) -> list[dict]:
    """Recent scans with task-state rollups (dashboard backing query)."""
    rows = await pool.fetch(
        """
        SELECT s.id::text AS scan_id, s.status, s.workflow,
               s.created_at, s.requested_by,
               coalesce(task_rollup.states, '{}'::jsonb) AS task_states
          FROM scans s
          LEFT JOIN LATERAL (
              SELECT jsonb_object_agg(state, n) AS states
                FROM (SELECT state, count(*) AS n
                        FROM tasks WHERE scan_id = s.id
                       GROUP BY state) agg
          ) task_rollup ON TRUE
         ORDER BY s.created_at DESC
         LIMIT $1
        """,
        max(1, min(int(limit), 100)),
    )
    return [dict(r) for r in rows]


async def list_findings(pool: asyncpg.Pool, *, scan_id: str | None = None,
                        state: str | None = None, severity: str | None = None,
                        is_new: bool | None = None,
                        limit: int = 50) -> list[dict]:
    """Filtered finding rows for the triage UI (all filters optional)."""
    clauses = ["1=1"]
    args: list[Any] = []
    if scan_id:
        args.append(scan_id)
        clauses.append(f"scan_id::text = ${len(args)}")
    if state:
        args.append(state)
        clauses.append(f"validation_state = ${len(args)}")
    if severity:
        args.append(severity)
        clauses.append(f"severity = ${len(args)}")
    if is_new is not None:
        args.append(is_new)
        clauses.append(f"is_new = ${len(args)}")
    args.append(max(1, min(int(limit), 200)))
    rows = await pool.fetch(
        "SELECT id::text, program_id::text, scan_id::text, type, value, "
        "severity, validation_state, confidence, is_new, metadata, first_seen "
        f"FROM findings WHERE {' AND '.join(clauses)} "
        "ORDER BY first_seen DESC LIMIT $" + str(len(args)),
        *args,
    )
    return [dict(r) for r in rows]


async def triage_finding(pool: asyncpg.Pool, finding_id: str, decision: str,
                         actor: str) -> dict | None:
    """Set validation_state on one finding; returns the row or None."""
    row = await pool.fetchrow(
        """UPDATE findings
              SET validation_state = $2,
                  validated_by = $3,
                  validated_at = now()
            WHERE id = $1::uuid
          RETURNING id::text, fingerprint, type, value, validation_state""",
        finding_id, decision, actor,
    )
    return dict(row) if row else None


async def metrics_snapshot(pool: asyncpg.Pool) -> dict:
    """Aggregated counters for the /metrics endpoint."""
    scans = {r["status"]: r["n"] for r in
             await pool.fetch("SELECT status, count(*) n FROM scans GROUP BY status")}
    tasks = {r["state"]: r["n"] for r in
             await pool.fetch("SELECT state, count(*) n FROM tasks GROUP BY state")}
    workers_alive = await pool.fetchval(
        "SELECT count(*) FROM worker_heartbeats "
        "WHERE last_seen > now() - interval '1 minute'"
    )
    total_findings = await pool.fetchval("SELECT count(*) FROM findings")
    new_findings = await pool.fetchval("SELECT count(*) FROM findings WHERE is_new")
    unvalidated = await pool.fetchval(
        "SELECT count(*) FROM findings WHERE validation_state='unvalidated'"
    )
    return {
        "scans": scans, "tasks": tasks,
        "workers_alive": int(workers_alive or 0),
        "findings_total": int(total_findings or 0),
        "findings_new": int(new_findings or 0),
        "findings_unvalidated": int(unvalidated or 0),
    }




def _json(obj: Any) -> str:
    import json as _j
    return _j.dumps(obj, separators=(",", ":"), default=str)


async def update_scan_status(pool: asyncpg.Pool, scan_id: str, status: str) -> None:
    await pool.execute(
        "UPDATE scans SET status=$2, updated_at=now() WHERE id=$1::uuid",
        scan_id, status,
    )


# --------------------------------------------------------------------- #
# Stage 6: report materialization (validated + NEW findings only).       #
# --------------------------------------------------------------------- #
async def report_material(pool: asyncpg.Pool, scan_id: str) -> dict | None:
    """Everything the report generator needs, nothing it must re-filter.

    Pillar B enforced IN THE QUERY: only ``validated`` findings are returned,
    and state-diffing (Pillar A cost model) restricts to ``is_new``. Rows are
    pre-ordered by severity so the renderer stays dumb. Returns None when the
    scan does not exist.
    """
    import json as _json

    scan = await pool.fetchrow(
        "SELECT id::text AS scan_id, workflow, status, created_at,"
        " requested_by FROM scans s WHERE s.id = $1::uuid",
        scan_id,
    )
    if scan is None:
        return None
    rows = await pool.fetch(
        """
        SELECT f.id::text AS finding_id, f.type, f.value, f.severity,
               f.confidence, f.metadata, f.first_seen
          FROM findings f
         WHERE f.scan_id = $1::uuid
           AND f.validation_state = 'validated'
           AND f.is_new
         ORDER BY CASE f.severity
                      WHEN 'critical' THEN 0
                      WHEN 'high'     THEN 1
                      WHEN 'medium'   THEN 2
                      WHEN 'low'      THEN 3
                      ELSE 4 END,
                  f.type, f.id
        """,
        scan_id,
    )
    findings: list[dict] = []
    for row in rows:
        item = dict(row)
        meta = item.pop("metadata", None)
        if isinstance(meta, str):
            try:
                meta = _json.loads(meta)
            except ValueError:
                meta = {}
        meta = meta if isinstance(meta, dict) else {}
        # The worker stores the FULL parsed finding as metadata — lift the
        # human-facing fields out of it.
        for key in ("name", "matched_at", "tags", "evidence",
                    "cvss_score", "cvss_vector"):
            if item.get(key) is None and meta.get(key) is not None:
                item[key] = meta[key]
        item["metadata"] = meta
        findings.append(item)
    return {"scan": dict(scan), "findings": findings}


async def task_states(pool: asyncpg.Pool, scan_id: str) -> Sequence[asyncpg.Record]:
    return await pool.fetch(
        "SELECT state, count(*) AS n FROM tasks WHERE scan_id=$1::uuid GROUP BY state",
        scan_id,
    )


async def heartbeat(pool: asyncpg.Pool, worker_id: str, capabilities: list[str]) -> None:
    await pool.execute(
        """
        INSERT INTO worker_heartbeats(worker_id, capabilities, last_seen)
        VALUES($1, $2, now())
        ON CONFLICT (worker_id)
        DO UPDATE SET capabilities = EXCLUDED.capabilities, last_seen = now()
        """,
        worker_id, capabilities,
    )


# --------------------------------------------------------------------- #
# Operational-clarity helpers (dashboard / live monitoring backing).
# Single round-trip each; used by GET /api/v1/dashboard + /api/v1/workers.
# --------------------------------------------------------------------- #
async def list_workers(pool: asyncpg.Pool) -> list[dict]:
    """Live worker fleet from heartbeats (GC removes rows stale >10 min)."""
    rows = await pool.fetch(
        "SELECT worker_id, capabilities, last_seen"
        " FROM worker_heartbeats ORDER BY last_seen DESC"
    )
    return [dict(r) for r in rows]


async def severity_histogram(pool: asyncpg.Pool) -> dict[str, int]:
    """Unvalidated+new findings per severity — the human-triage backlog."""
    rows = await pool.fetch(
        "SELECT severity, count(*) AS n FROM findings"
        " WHERE validation_state = 'unvalidated' AND is_new"
        " GROUP BY severity"
    )
    return {(r["severity"] or "info"): int(r["n"]) for r in rows}


async def recent_events(pool: asyncpg.Pool, limit: int = 12) -> list[dict]:
    """Audit-log tail for the live activity feed (bounded 1..50)."""
    rows = await pool.fetch(
        "SELECT ts, actor, action, subject, decision FROM audit_log"
        " ORDER BY ts DESC LIMIT $1",
        max(1, min(int(limit), 50)),
    )
    return [dict(r) for r in rows]



async def audit_event(pool: asyncpg.Pool, *, actor: str, action: str, subject: str | None,
                      decision: str, details: dict | None = None) -> None:
    await pool.execute(
        """INSERT INTO audit_log(actor, action, subject, decision, details)
           VALUES($1, $2, $3, $4, $5::jsonb)""",
        actor, action, subject, decision, _json(details or {}),
    )


async def wait_for_db(dsn: str, attempts: int = 30, delay: float = 2.0) -> asyncpg.Pool:
    """Retry loop used at container start while dependencies come up.

    Uses ``asyncio.sleep`` (never the blocking ``time.sleep``) so the retry
    never stalls the event loop the caller is running on.
    """
    import asyncio

    last_exc: Exception | None = None
    for i in range(attempts):
        try:
            return await connect(dsn)
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            log.warning("database not ready (attempt %d/%d): %s", i + 1, attempts, exc)
            await asyncio.sleep(delay)
    raise RuntimeError(f"database unreachable after {attempts} attempts") from last_exc
