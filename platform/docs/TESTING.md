# Testing Guide

Status: **the suite runs green locally** (366 passed; Python 3.14,
pytest 9). Fakes stand in for PostgreSQL/Redis/Docker so no services are
needed.

## Layers

| Layer | Files | Dependencies | Notes |
|---|---|---|---|
| Unit – scope | `tests/test_scope.py` | none | security core |
| Unit – workflows | `tests/test_workflows.py`, `test_upgrades.py` | PyYAML | loader/planner/registry gates |
| Unit – tools parsers | `tests/test_tools.py`, `test_edge_cases.py` | none | JSONL/noise/unicode/long-line tolerance |
| Contract – executor | `tests/test_executor.py`, `test_tools.py::TestExecutorStdin` | local python only | timeout/cap/stdin/env-passthrough/not-found/exit codes |
| Integration – master API | `tests/test_master_api.py` | **fakes** (`FakePool`, `FakeQueue`) via TestClient | auth, scope gates, fanout/dispatch, metrics, dashboard |
| Integration – worker ctx | `tests/test_worker_context.py` | fakes + monkeypatched DB helper | input materialization, dedup, caps, dead-letter on bad params |
| Concurrency / perf | `tests/test_concurrency.py`, `test_master_api.py::TestRecordFindingsBatch` | none/fakes | token-bucket pacing, batch invariants (1 txn, executemany), fingerprint determinism under threads |

Fakes live in [`common/testing.py`](../common/testing.py): `FakePool`
(scripted canned results + SQL recording + transaction/executemany tracking),
`FakeQueue` (FIFO consume/ack contract), `make_test_settings()`.
Any drift between the fakes and real clients fails a test by construction.

## Run

```bash
cd platform && python -m pytest tests -q        # ~3s, no Docker needed
# optional coverage:
python -m pytest tests -q --cov=common --cov=master --cov=worker --cov-report=term-missing
```

Windows note: there is no pytest-timeout plugin installed. When running on
a dev box where a runaway test could spin, launch pytest as a child process
with an external watchdog (Start-Process + Wait-Process -Timeout N +
Stop-Process) instead of blocking the shell — see the verified procedure in
the project history. Any consume-loop regression now fails fast via the
backoff contract tests rather than hanging.

## Deliberately NOT unit-tested (needs real infra — covered by scripts/validate_stage1.py)

* asyncpg SQL semantics (migrations run against real PG in compose)
* Redis XAUTOCLAIM behavior (validated end-to-end post-deploy)
* Kali tool binaries' actual CLI flags (pinned versions; parser fixtures
  mirror documented output schemas)
