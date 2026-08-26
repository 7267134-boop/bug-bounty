"""Typed tool-wrapper contract (Strategy pattern).

Every security tool implements this interface. The worker never invokes a
binary directly; it only calls ``ToolWrapper`` methods, guaranteeing uniform
scope checks, argv construction, rate limiting and output parsing.

Data-flow model (Unix philosophy):
* tools declare what finding types they ``consumes`` and ``produces``;
* the worker materializes consumed findings (from PostgreSQL) into a temp
  input file when the wrapper sets ``needs_input_file``;
* wrappers that only read stdin implement ``stdin_data`` instead
  (executor feeds it via communicate()).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


class ToolNotPermitted(PermissionError):
    """Raised when a tool is not registered or not in the capability allowlist."""


class ToolExecutionError(RuntimeError):
    """Raised for non-retryable tool-level failures (bad params, parse errors)."""


@dataclass(frozen=True)
class ToolContext:
    """Everything a wrapper may need to build its command line."""

    task_id: str
    scan_id: str
    program_id: str
    step_name: str
    target: str                       # normalized + scope-validated ('' for once-steps)
    params: dict[str, Any]
    attempt: int
    timeout_secs: int
    max_output_bytes: int
    workdir: str                      # per-task scratch dir on tmpfs
    rate_limit_rps: float = 10.0
    # Finding values grouped by type, queried from the findings store for this
    # scan - populated by the worker for every type in wrapper.consumes.
    inputs: dict[str, list[str]] = field(default_factory=dict)
    # Materialized input file inside workdir (set when needs_input_file=True).
    input_file: str | None = None


@dataclass
class ExecResult:
    """Raw process outcome from the executor."""

    return_code: int | None
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.return_code == 0 and not self.timed_out


class ToolWrapper(ABC):
    """Base class every tool must implement."""

    name: str = "abstract"              # unique registry key, e.g. 'subfinder'
    description: str = ""
    binary: str = ""                    # executable expected in $PATH
    output_mode: str = "stdout"         # 'stdout' | 'json_file' | 'dir'
    rate_limit_rps: float = 10.0        # politeness ceiling per program policy
    produces: list[str] = []            # finding types emitted
    consumes: list[str] = []            # finding types read from the store
    needs_input_file: bool = False      # worker writes ctx.input_file from ctx.inputs
    allowed_params: set[str] = set()

    def validate_params(self, params: dict[str, Any]) -> dict[str, Any]:
        """Whitelist-and-coerce parameters. Reject unknown keys by default."""
        unknown = set(params) - set(self.allowed_params)
        if unknown:
            raise ToolExecutionError(f"{self.name}: unknown params {sorted(unknown)}")
        return dict(params)

    @abstractmethod
    def build_argv(self, ctx: ToolContext) -> list[str]:
        """Return the exact argv list to execute. MUST NOT use shell syntax."""

    @abstractmethod
    def parse(self, result: ExecResult, ctx: ToolContext) -> list[dict]:
        """Normalize raw output into typed finding dicts."""

    def stdin_data(self, ctx: ToolContext) -> bytes | None:
        """Return bytes to feed the process via stdin, or None."""
        return None

    # ---- batch execution (tools lacking multi-target input) -------------
    #
    # Some tools (wpscan, sqlmap single-URL mode...) accept ONE target per
    # process. Such wrappers set ``batch_mode = True`` and implement
    # ``build_argv_batch`` returning one argv list per target; the executor
    # runs them sequentially inside the SAME sandboxed context and merges
    # the outcomes into a single ExecResult.
    batch_mode: bool = False

    def build_argv_batch(self, ctx: ToolContext) -> list[list[str]]:
        raise NotImplementedError(f"{self.name} does not support batching")

    def check_binary(self) -> bool:
        """True when the binary exists in PATH (used by readiness probes)."""
        if not self.binary:
            return True  # built-ins that drive the interpreter itself
        import shutil

        return shutil.which(self.binary) is not None
