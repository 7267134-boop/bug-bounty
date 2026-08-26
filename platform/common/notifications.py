"""Notification hub (notify-style) - env-gated webhook dispatch.

Set ``WEBHOOK_URL`` to any JSON-accepting endpoint (Discord/Slack-compatible
proxies, custom receivers). Failures are logged but NEVER break the pipeline.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import urllib.request

log = logging.getLogger("common.notify")


def _post_json(url: str, payload: dict, timeout: float = 5.0) -> bool:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return 200 <= resp.status < 300


async def notify_event(event: str, details: dict | None = None,
                       text: str | None = None) -> bool:
    """Fire-and-forget webhook notification. Returns True when delivered."""
    url = os.environ.get("WEBHOOK_URL", "").strip()
    if not url:
        log.info("notification skipped (no WEBHOOK_URL)", extra={"event": event})
        return False
    payload = {"event": event, "details": details or {}}
    if text:
        payload["text"] = text
    try:
        delivered = await asyncio.to_thread(_post_json, url, payload)
    except Exception as exc:  # noqa: BLE001 - notifications must never fail scans
        log.warning("webhook delivery failed", extra={"event": event, "error": str(exc)})
        return False
    log.info("notification delivered", extra={"event": event, "ok": delivered})
    return delivered
