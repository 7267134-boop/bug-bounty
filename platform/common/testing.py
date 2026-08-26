"""Reusable test doubles: PostgreSQL pool and Redis queue fakes.

Enables fast, hermetic tests of master/worker logic without Docker,
PostgreSQL, or Redis. These are intentionally minimal - implement only what
the production call sites use, so drift surfaces as test failures.
"""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any


# --------------------------------------------------------------------- #
# Settings
# --------------------------------------------------------------------- #
def make_test_settings(**overrides) -> Any:
    """Settings suitable for tests (no external services contacted)."""
    import os

    from common.config import Settings

    os.environ.setdefault("MASTER_API_TOKEN", "test-token")
    defaults = dict(
        pg_host="localhost", pg_password="x",
        redis_url="redis://localhost:6399/0",
        api_token="test-token",
        stale_requeue_secs=60,
        block_secs=0,
        task_timeout_secs=5,
        max_output_bytes=10_000,
        worker_rate_rps=1000.0,
        log_level="WARNING",
    )
    defaults.update(overrides)
    return Settings(**defaults)


# --------------------------------------------------------------------- #
# Queue fake (mirrors common.redis_client.TaskQueue surface used by workers)
# --------------------------------------------------------------------- #
@dataclass
class FakeQueue:
    stream: list[dict] = field(default_factory=list)
    acked: list[str] = field(default_factory=list)
    enqueued_payloads: list[dict] = field(default_factory=list)

    async def connect(self) -> None: ...

    async def close(self) -> None: ...

    async def ping(self) -> bool:
        return True

    async def enqueue(self, payload: dict) -> str:
        self.enqueued_payloads.append(payload)
        entry = f"entry-{len(self.enqueued_payloads)}"
        self.stream.append(payload)
        return entry

    async def consume(self, consumer: str, count: int = 1, block_ms: int = 0):
        if not self.stream:
            await asyncio.sleep(0)
            return []
        payload = self.stream.pop(0)
        return [(f"id-{len(self.acked)}", payload)]

    async def ack(self, entry_id: str) -> None:
        self.acked.append(entry_id)

    async def reclaim_stale(self, min_idle_ms: int) -> int:
        return 0


# --------------------------------------------------------------------- #
# Pool fake: records executed SQL and serves canned results keyed by
# substring match on the query text.
# --------------------------------------------------------------------- #
@dataclass
class FakeResult:
    _rows: list

    def __iter__(self):
        return iter(self._rows)

    def __len__(self):
        return len(self._rows)


class FakeConn:
    def __init__(self, pool: "FakePool"):
        self.pool = pool

    async def fetchrow(self, query: str, *args):
        return await self.pool.fetchrow(query, *args)

    async def fetchval(self, query: str, *args):
        return await self.pool.fetchval(query, *args)

    async def fetch(self, query: str, *args):
        return await self.pool.fetch(query, *args)

    async def execute(self, query: str, *args):
        self.pool.executed.append((query.strip()[:120], args))
        return "OK"

    async def executemany(self, query: str, args_seq):
        self.pool.executemany_calls.append((query.strip()[:120],
                                            len(list(args_seq))))
        return "OK"

    @asynccontextmanager
    async def transaction(self):
        self.pool.transactions += 1
        yield


class FakePool:
    """Scriptable asyncpg stand-in.

    ``canned`` maps a lowercase substring of the query to either a list of
    dict-like rows (for fetch*) or a scalar (for fetchval).
    """

    def __init__(self, canned: dict[str, Any] | None = None):
        self.canned = canned or {}
        self.executed: list[tuple[str, tuple]] = []
        self.executemany_calls: list[tuple[str, int]] = []
        self.transactions: int = 0

    def _match(self, query: str) -> Any | None:
        q = " ".join(query.split()).lower()
        for needle, value in self.canned.items():
            if needle.lower() in q:
                return value
        return None

    async def connect(self):  # context-manager style acquisition
        return self

    @asynccontextmanager
    async def acquire(self):
        """Compatible with ``async with pool.acquire() as conn:``."""
        yield FakeConn(self)

    async def execute(self, query: str, *args):
        self.executed.append((query.strip()[:120], args))
        return "OK"

    async def executemany(self, query: str, args_seq):
        self.executemany_calls.append((query.strip()[:120], len(list(args_seq))))
        return "OK"

    @asynccontextmanager
    async def transaction(self):
        self.pool.transactions += 1
        yield

    async def fetchrow(self, query: str, *args):
        value = self._match(query)
        if isinstance(value, list) and value:
            return value[0]
        return None

    async def fetchval(self, query: str, *args):
        value = self._match(query)
        if value is not None and not isinstance(value, list):
            return value
        return True

    async def fetch(self, query: str, *args):
        value = self._match(query)
        if isinstance(value, list):
            return value
        return []


def row(**kwargs) -> dict:
    """Dict standing in for an asyncpg Record."""
    return kwargs


# --------------------------------------------------------------------- #
# Deterministic clock helpers for timing-sensitive tests
# --------------------------------------------------------------------- #
class VirtualLoopClock:
    """Small helper asserting elapsed wall-time windows without sleeps."""

    @staticmethod
    async def measure(coro_factory, min_s: float = 0.0, max_s: float = 30.0):
        start = time.monotonic()
        await coro_factory()
        elapsed = time.monotonic() - start
        assert min_s <= elapsed <= max_s, f"elapsed {elapsed:.3f}s outside [{min_s},{max_s}]"
        return elapsed
