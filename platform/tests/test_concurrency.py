"""Concurrency behavior: rate limiting, dedup stability, queue semantics."""

import asyncio
import time

from common.ratelimit import TokenBucket
from common.testing import FakeQueue


class TestTokenBucketConcurrency:
    def test_parallel_acquires_respect_rate(self):
        async def scenario():
            bucket = TokenBucket(rate=200.0, capacity=2.0)
            start = time.monotonic()
            await asyncio.gather(*(bucket.acquire() for _ in range(6)))
            return time.monotonic() - start

        elapsed = asyncio.run(scenario())
        # 2 burst + 4 at 200rps = >=0.02s of forced pacing; generous upper bound
        assert 0.015 <= elapsed < 1.0

    def test_single_acquire_never_waits_on_full_burst(self):
        async def scenario():
            b = TokenBucket(rate=1.0, capacity=5.0)
            t0 = time.monotonic()
            await asyncio.gather(*(b.acquire() for _ in range(5)))
            return time.monotonic() - t0

        assert asyncio.run(scenario()) < 0.1


class TestFakeQueueSemantics:
    """The queue fake must mirror the real consume/ack contract."""

    def test_fifo_consume_and_ack(self):
        async def scenario():
            q = FakeQueue()
            await q.connect()
            first = await q.enqueue({"task_id": "a"})
            second = await q.enqueue({"task_id": "b"})
            got1 = await q.consume("w", block_ms=0)
            got2 = await q.consume("w", block_ms=0)
            empty = await q.consume("w", block_ms=0)
            await q.ack(got1[0][0])
            await q.ack(got2[0][0])
            return first, second, got1[0][1]["task_id"], got2[0][1]["task_id"], \
                empty, len(q.acked)

        entry_a, _e2, t1, t2, empty, acks = asyncio.run(scenario())
        assert (t1, t2) == ("a", "b")          # FIFO preserved
        assert empty == []                      # exhausted stream
        assert acks == 2

    def test_enqueue_returns_unique_entry_ids(self):
        async def scenario():
            q = FakeQueue()
            ids = [await q.enqueue({"n": i}) for i in range(3)]
            return len(set(ids))

        assert asyncio.run(scenario()) == 3


class TestFindingsDedupStability:
    def test_fingerprint_order_independent_across_threads(self):
        from concurrent.futures import ThreadPoolExecutor

        from common.ids import entity_fingerprint

        values = [f"h{i}.example.com" for i in range(50)]
        with ThreadPoolExecutor(max_workers=8) as pool:
            hashes = list(pool.map(
                lambda v: entity_fingerprint("p", "subdomain", v), values * 4))
        assert len(set(hashes)) == 50           # deterministic under concurrency
