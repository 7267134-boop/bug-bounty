"""Async token bucket - politeness / rate limiting for tool execution."""

from __future__ import annotations

import asyncio
import time


class TokenBucket:
    """Classic token-bucket limiter (thread-safe within one event loop).

    ``rate`` tokens/second sustained, ``capacity`` burst size. Workers acquire
    a token before every tool launch so program-level RPS ceilings are never
    exceeded regardless of concurrency.
    """

    def __init__(self, rate: float, capacity: float | None = None):
        if rate <= 0:
            raise ValueError("rate must be positive")
        self.rate = float(rate)
        self.capacity = float(capacity if capacity is not None else max(1.0, rate))
        self._tokens = self.capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> float:
        """Reserve one token. Returns the wait time in seconds (0 if instant)."""
        waited = 0.0
        while True:
            async with self._lock:
                now = time.monotonic()
                self._tokens = min(
                    self.capacity, self._tokens + (now - self._updated) * self.rate
                )
                self._updated = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return waited
                deficit = (1.0 - self._tokens) / self.rate
            await asyncio.sleep(deficit)
            waited += deficit
