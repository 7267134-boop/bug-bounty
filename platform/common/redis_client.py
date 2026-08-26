"""Redis Streams task queue with consumer groups.

Durability & crash-safety model:

* Tasks live durably in PostgreSQL first; the stream is the dispatch channel.
* Workers consume via a consumer group (XREADGROUP) so each delivery has at
  most one owner; completion is signalled by XACK **after** the DB row is in
  its terminal state.
* A master-side reclaimer moves entries that were delivered but never ACKed
  (worker crash) back to the queue after ``stale_requeue_secs`` - idempotency
  keys make redelivery safe.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any

from redis import asyncio as aioredis

log = logging.getLogger("common.queue")


class TaskQueue:
    def __init__(self, redis_url: str, stream_key: str, consumer_group: str):
        self.redis_url = redis_url
        self.stream_key = stream_key
        self.group = consumer_group
        self.client: aioredis.Redis | None = None

    async def connect(self) -> None:
        self.client = aioredis.from_url(self.redis_url, decode_responses=True)
        await self.client.ping()
        # Idempotently create the consumer group.
        try:
            await self.client.xgroup_create(self.stream_key, self.group, id="0", mkstream=True)
            log.info("consumer group created", extra={"group": self.group})
        except Exception as exc:  # BUSYGROUP = already exists
            if "BUSYGROUP" not in str(exc):
                raise

    async def close(self) -> None:
        if self.client:
            await self.client.aclose()

    async def ping(self) -> bool:
        assert self.client
        try:
            return bool(await self.client.ping())
        except Exception:  # noqa: BLE001
            return False

    # ------------------------------------------------------------------ #
    async def enqueue(self, payload: dict[str, Any]) -> str:
        """Add one task message to the stream. Returns the stream entry ID."""
        assert self.client, "queue not connected"
        body = dict(payload)
        body.setdefault("issued_at_epoch", time.time())
        entry_id = await self.client.xadd(
            self.stream_key,
            {"payload": json.dumps(body, separators=(",", ":"))},
        )
        log.info(
            "task enqueued",
            extra={"task_id": body.get("task_id"), "entry_id": str(entry_id)},
        )
        return str(entry_id)

    async def consume(self, consumer: str, count: int = 1, block_ms: int = 5000):
        """Read pending-to-this-consumer messages. Returns list of (id, dict)."""
        assert self.client, "queue not connected"
        rows = await self.client.xreadgroup(
            self.group, consumer, {self.stream_key: ">"}, count=count, block=block_ms
        )
        results: list[tuple[str, dict]] = []
        for _stream, messages in rows or []:
            for entry_id, fields in messages:
                try:
                    results.append((str(entry_id), json.loads(fields.get("payload", "{}"))))
                except json.JSONDecodeError:
                    log.error("poison message discarded", extra={"entry_id": str(entry_id)})
                    await self.ack(entry_id)
        return results

    async def ack(self, entry_id: str) -> None:
        assert self.client
        await self.client.xack(self.stream_key, self.group, entry_id)

    async def reclaim_stale(self, min_idle_ms: int) -> int:
        """XAUTOCLAIM entries idle beyond threshold; re-enqueue them once.

        Returns the number of reclaimed messages. The claimed original is
        ACKed so it will not be double-processed by this path again.
        """
        assert self.client, "queue not connected"
        cursor = "0-0"
        reclaimed = 0
        while True:
            result = await self.client.xautoclaim(
                self.stream_key, self.group, "reclaimer",
                min_idle_time=min_idle_ms, start_id=cursor, count=10,
            )
            cursor, messages, _deleted = result[0], result[1], result[2] if len(result) > 2 else []
            if not messages:
                break
            for entry_id, fields in messages:
                try:
                    payload = json.loads(fields.get("payload", "{}"))
                except json.JSONDecodeError:
                    payload = {}
                payload["attempt"] = int(payload.get("attempt", 1)) + 1
                payload["reclaimed"] = True
                await self.enqueue(payload)
                await self.ack(entry_id)
                reclaimed += 1
                log.warning(
                    "stale task reclaimed and requeued",
                    extra={"task_id": payload.get("task_id"), "entry_id": str(entry_id)},
                )
            if cursor == "0-0":
                break
        return reclaimed


def new_consumer_name(worker_id: str) -> str:
    """Stable-per-boot consumer name so crashed workers' PELs get reclaimed."""
    return f"{worker_id}-{uuid.uuid4().hex[:8]}"
