"""ID generation and idempotency-key helpers."""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any


def new_id() -> str:
    """Random UUID4 (hex, no dashes)."""
    return uuid.uuid4().hex


def canonical(obj: Any) -> str:
    """Deterministic serialization used as input to idempotency keys."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def idempotency_key(*parts: Any) -> str:
    """Stable SHA-256 over canonicalized parts.

    The same logical unit of work (scan + step + target + tool + params)
    always produces the same key, so re-planning after a crash cannot create
    duplicate executions.
    """
    digest = hashlib.sha256(canonical(parts).encode()).hexdigest()
    return digest


def entity_fingerprint(program_id: str, finding_type: str, value: str) -> str:
    """Stable cross-scan identity for a discovered entity.

    Used by the findings store for deduplication and state diffing: the same
    (program, type, value) triple always maps to one fingerprint, enabling
    'is this NEW since my last scan?' queries.
    """
    normalized = f"{program_id.strip().lower()}|{finding_type.strip().lower()}|{value.strip().lower()}"
    return hashlib.sha256(normalized.encode()).hexdigest()
