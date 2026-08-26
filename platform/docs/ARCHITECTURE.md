# Architecture Reference (consolidated)

Single source of truth for component roles, data flow, boundaries,
assumptions and the operational model. Component-level details live next to
the code; this page is the map.

## 1. Components & ownership

| Component | Tech | Owns (single-writer) | Never does |
|---|---|---|---|
| **Master** (`master/`) | FastAPI, asyncpg, redis | planning, scope gate #1, task state transitions, dispatch gating, stale reclaim, scan finalization, heartbeat GC, audit writes for master actions | executing tools; network egress to targets |
| **Worker** (`worker/`) | Python + Kali binaries | tool execution, scope gate #2, capability enforcement, finding persistence for its tasks, retry/dead-letter decisions | accepting connections; touching master-owned state outside its own task rows |
| **PostgreSQL** | 16 | durable truth: programs/scope/scans/tasks/findings/audit/heartbeats | – |
| **Redis** | 7 Streams | dispatch channel only (consumer groups, XAUTOCLAIM) | durable state |

## 2. Data flow

```
submit ──▶ auth ──▶ SCOPE GATE #1 ──▶ plan(YAML, deps, when-gates)
                                    ──▶ INSERT tasks (+idempotency_key)
                                    ──▶ enqueue ROOT tasks only
master background loop (30s):
    reclaim stale deliveries → promote ready tasks (deps succeeded
    AND routing gate satisfied) → finalize terminal scans → notify
workers (N, isolated):
    XREADGROUP ──▶ claim row ──▶ SCOPE GATE #2 ──▶ capability gate
    ──▶ materialize inputs (findings store) ──▶ token-bucket launch
    ──► parse ──► record_findings(fingerprints, is_new) ──► retry/dead-letter ──► ACK
```

**Inter-tool data flows through PostgreSQL**, never ad-hoc files: a wrapper
declares `consumes`/`produces` finding types; the worker materializes them
into a tmpfs input file (capped at 100k lines).

## 3. State machines

Task: `queued`(pending/enqueued via `dispatched`) → `running` →
`succeeded | failed | dead`; queued dependents of a failed/dead step become
`aborted` (recursive CTE). Scan: `pending→running→completed|failed`.

Crash windows are safe by construction:
* crash between XADD and `dispatched=TRUE` ⇒ one redundant redelivery;
  the atomic claim (`WHERE state IN ('queued','running')`) makes it a no-op.
* worker death mid-run ⇒ delivery sits in the consumer PEL until
  `XAUTOCLAIM` requeues it after `STALE_REQUEUE_SECS`.

## 4. Trust boundaries

| Boundary | Enforcement |
|---|---|
| Internet → Master | token (constant-time), pydantic models, no free-form fields |
| Master → Worker | typed `TaskMessage`; worker re-validates scope (gate #2) and capabilities |
| Worker → OS | argv-list only (`shell=False`), rlimits, timeout→SIGKILL group, output caps, minimal env, non-root/read-only container |
| Tool output → store | namespace filtering where a tool can emit foreign assets (amass, uncover); fingerprints deduplicate |

Known residual risk: workers hold DB credentials with broad rights.
Hardening backlog: dedicated least-privilege PG role per worker.

## 5. Cost model (Triad)

1. **Algorithmic automation** — dependency chains + `when.has_finding_type`
   gates (e.g. massdns drops dead domains before probing; nmap runs only on
   discovered ports; dalfox waits for `url_param`). Cheap signals route
   expensive tools.
2. **Human triage** — dashboard exposes `unvalidated` + `is_new` findings
   only; Validate/Refute writes `validation_state` (+ who/when).
3. **AI/MCP finalizer** *(Stage 5, pending)* — consumes ONLY
   `validation_state='validated'` rows through the same typed wrappers.

## 6. Assumptions & constraints

* Kali/Linux hosts; Docker Compose deployment; single-master topology
  (scale-out = more workers, never a second writer).
* Security tool binaries are pre-installed/pinned in the worker image;
  provider API keys arrive solely via `WORKER_ENV_PASSTHROUGH`.
* Authorized bug-bounty targets only — enforced by default-deny scope at
  two independent layers.

## 7. Extension points

* New tool: `@register` wrapper (declare consumes/produces) → master
  `ALLOWED_TOOLS` → `WORKER_CAPABILITIES` → workflow step. Fail-closed at
  every layer.
* New routing signal: emit a new finding `type`; gates key off types.
* New sink: notifications hub / audit log already carry structured events.
