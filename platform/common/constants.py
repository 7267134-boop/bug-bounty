"""Shared domain constants (single source of truth, no per-module copies)."""

from __future__ import annotations

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
VALIDATION_STATES: tuple[str, ...] = ("unvalidated", "validated", "refuted")
TASK_STATES: tuple[str, ...] = (
    "queued", "running", "succeeded", "failed", "aborted", "dead",
)
# Terminal states from which a scan's rollup derives its outcome.
TASK_FAILURE_STATES: tuple[str, ...] = ("failed", "aborted", "dead")
SCAN_STATUSES: tuple[str, ...] = (
    "pending", "running", "completed", "failed", "cancelled",
)

# Finding dict keys consulted (in order) when deriving an entity value.
FINDING_VALUE_KEYS: tuple[str, ...] = (
    "value", "subdomain", "url", "host_port", "host", "id",
)
