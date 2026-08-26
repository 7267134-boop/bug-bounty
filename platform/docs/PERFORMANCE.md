# Performance & Efficiency Review (v0.3)

## Language strategy: Python control plane, Go data plane

The orchestration/control plane (auth, scope, planning, state machines,
reporting) is I/O-bound and benefits from Python's asyncpg/redis/FastAPI
ecosystem — measured bottlenecks there are network waits, not CPU. The
**data plane** (tool execution) already runs Go binaries (subfinder, httpx,
nuclei, …): the platform is effectively "Go where it matters" without a
rewrite. A future Go rewrite candidate, with explicit triggers:

| Candidate | Trigger to port | Why not now |
|---|---|---|
| Findings ingest service (>5k findings/min sustained) | batched writer saturates >30% of one core | current volume ≪ threshold |
| URL classification/routing (Stage 3) | regex filtering >50ms per 100k URLs | pure-Python set ops are µs-scale today |
| Dashboard aggregation | p95 API latency >300ms | single indexed query + LATERAL rollup |

Adding a second language now would triple the test/deploy surface for no
measurable gain — rejected per YAGNI; revisit at the stated triggers.

## Implemented optimizations

1. **Batched findings writes** (`common/db.record_findings`):
   one connection + one `ANY($2)` membership query + one `executemany`
   inside a transaction — replaces per-finding acquire/query/insert.
   In-batch dedup collapses duplicates before hitting the DB.
   Perf invariant enforced by `test_master_api.py::TestRecordFindingsBatch`.
2. **Dashboard backing queries**: single-round-trip `/api/v1/dashboard`;
   `list_scans` uses an indexed `LATERAL` rollup instead of N+1 task counts;
   limit clamped server-side (1..100).
3. **Input materialization caps**: worker caps upstream input files at
   100k lines and output capture at `MAX_OUTPUT_BYTES` — bounded memory
   regardless of tool behavior.
4. **Rate-limited launches**: token bucket prevents self-inflicted overload;
   concurrency bounded by semaphore (`WORKER_CONCURRENCY`) and container
   pids/mem/cpus limits.
5. **Static dashboard asset**: zero-framework HTML (no CDN/build step),
   sessionStorage token, 5s polling of one aggregated endpoint.

## Efficiency invariants enforced by tests

* findings batch ⇒ exactly 1 transaction + 1 executemany call
* fingerprint determinism across threads (dedup correctness under concurrency)
* token-bucket pacing bounds (burst instant, sustained rate respected)
* queue FIFO + ack contract mirrored by the fake (contract drift fails fast)
