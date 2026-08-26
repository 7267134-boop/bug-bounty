"""Typed event / message models exchanged between master and worker."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

# Strict charset for tool names and step names flowing over the queue.
import re

_NAME_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,64}$")


class TaskMessage(BaseModel):
    """The single message type placed on the Redis task stream."""

    task_id: str
    idempotency_key: str
    scan_id: str
    program_id: str
    step_name: str
    tool: str
    target: str
    params: dict[str, Any] = Field(default_factory=dict)
    attempt: int = 1
    max_attempts: int = 3
    issued_at_epoch: float = 0.0

    @field_validator("step_name")
    @classmethod
    def _step_ok(cls, v: str) -> str:
        if not _NAME_RE.match(v):
            raise ValueError(f"illegal step name: {v!r}")
        return v

    @field_validator("tool")
    @classmethod
    def _tool_ok(cls, v: str) -> str:
        if not _NAME_RE.match(v):
            raise ValueError(f"illegal tool name: {v!r}")
        return v


class TaskResult(BaseModel):
    """Worker -> platform result record (persisted on the task row)."""

    task_id: str
    ok: bool
    exit_code: int | None = None
    duration_ms: int = 0
    summary: str = ""
    findings_count: int = 0
    error: str | None = None
    retryable: bool = False
