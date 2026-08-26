# Manual Parameter Tuning Checklist (PENDING)

> **Status: waiting for final tuning data.** Every value below ships as a
> safe engineering default chosen for correctness, not peak throughput.
> When the final workload profile / operator preferences arrive, work top
> to bottom through this table, then re-run `python -m pytest tests -q`
> plus a staging soak test before promoting values to production.

## How to tune

1. Set the environment variable in `.env` (see `.env.example`).
2. Restart the affected service; all knobs are read at startup only.
3. Validate: worker knobs → watch logs for `consume error; backing off`
   (`delay_secs` should stay near base under transient faults).
4. Record the chosen value + rationale in the table below.

## Parameters

| Env var | Settings field | Default | Valid range | Tuning goal | Status |
|---|---|---|---|---|---|
| `WORKER_CONCURRENCY` | `worker_concurrency` | `2` | 1–16 | saturate tool I/O without starving PG/Redis | **TUNING PENDING** |
| `WORKER_RATE_RPS` | `worker_rate_rps` | `10` | 0.5–1000 | politeness vs. throughput per program scope | **TUNING PENDING** |
| `TASK_TIMEOUT_SECS` | `task_timeout_secs` | `600` | 30–3600 | kill stuck tools early enough | **TUNING PENDING** |
| `MAX_OUTPUT_BYTES` | `max_output_bytes` | `1000000` | 10k–10M | parser evidence vs. memory bound | **TUNING PENDING** |
| `BLOCK_SECS` | `block_secs` | `5` | 0–60 | Redis XREADGROUP long-poll latency | **TUNING PENDING** |
| `STALE_REQUEUE_SECS` | `stale_requeue_secs` | `900` | 120–3600 | requeue crashed workers fast w/o dupes | **TUNING PENDING** |
| `CONSUME_ERROR_BACKOFF_SECS` | `consume_error_backoff_secs` | `3` | 0.5–30 | base delay of consume-loop error backoff | **TUNING PENDING** |
| `CONSUME_ERROR_BACKOFF_MAX_SECS` | `consume_error_backoff_max_secs` | `30` | 5–300 | backoff ceiling during prolonged outages | **TUNING PENDING** |

## Invariants (must hold after ANY tuning change)

* Backoff is exponential (`base * 2^(n-1)`), capped at max, reset by one
  success — enforced by `tests/test_full_coverage.py::TestWorkerLoops`.
* Scope gates are never tunable. Default-deny / hard-blocks are fixed code.
* Output caps and input line caps (100k) bound memory regardless of tuning.
