"""Tool registry and worker capability gate.

Registration is explicit: nothing runs unless (a) it is registered here AND
(b) its name appears in the worker's ``WORKER_CAPABILITIES`` allowlist.

Stage 2+ extension point::

    @register
    class SubfinderTool(ToolWrapper):
        name = "subfinder"
        binary = "subfinder"
        ...
"""

from __future__ import annotations

import logging
from typing import Callable, TypeVar

from .base import ExecResult, ToolContext, ToolNotPermitted, ToolWrapper

log = logging.getLogger("worker.tools")

_REGISTRY: dict[str, ToolWrapper] = {}

T = TypeVar("T", bound=type)


def register(cls: T) -> T:
    """Class decorator adding a ToolWrapper to the global registry."""
    if not getattr(cls, "name", None) or cls.name == "abstract":
        raise ValueError("tool wrapper must define a unique name")
    _REGISTRY[cls.name] = cls()  # type: ignore[abstract]
    return cls


def get_tool(name: str) -> ToolWrapper | None:
    return _REGISTRY.get(name)


def known_tools() -> list[str]:
    return sorted(_REGISTRY)


def resolve_tool(name: str, capabilities: list[str]) -> ToolWrapper:
    """Fetch a tool enforcing the capability allowlist (fail-closed)."""
    tool = _REGISTRY.get(name)
    if tool is None:
        raise ToolNotPermitted(f"tool {name!r} is not registered on this worker")
    if name not in capabilities:
        raise ToolNotPermitted(
            f"tool {name!r} is registered but missing from WORKER_CAPABILITIES"
        )
    return tool


# --------------------------------------------------------------------- #
# Built-in tools available from Stage 1.
# --------------------------------------------------------------------- #
@register
class BuiltinNoop(ToolWrapper):
    """Pipeline validation tool: echoes its input, touches nothing.

    Used by workflows/smoke.yaml to prove end-to-end orchestration without
    any security-tool side effects.
    """

    name = "builtin.noop"
    description = "No-op echo tool for pipeline validation."
    binary = ""                       # executed with sys.executable, see below
    rate_limit_rps = 100.0
    output_mode = "stdout"
    produces = ["noop_echo"]
    consumes: list[str] = []
    allowed_params = {"message"}

    import re as _re

    _SAFE_MSG = _re.compile(r"^[A-Za-z0-9 .:_\-]{0,200}$")

    def validate_params(self, params: dict) -> dict:
        msg = str(params.get("message", "ok"))
        if not self._SAFE_MSG.match(msg):
            raise ValueError("params.message contains forbidden characters")
        return {"message": msg}

    def build_argv(self, ctx: ToolContext) -> list[str]:
        message = self.validate_params(ctx.params)["message"]
        return [
            "python3", "-c",
            "import json,sys,time;"
            "print(json.dumps({'echo': sys.argv[1],"
            "'target': sys.argv[2],'ts': time.time()}))",
            message,
            ctx.target,
        ]

    def parse(self, result: ExecResult, ctx: ToolContext) -> list[dict]:
        import json

        try:
            record = json.loads(result.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return []
        return [{"type": "noop_echo", "target": ctx.target, **record}]


__all__ = [
    "ExecResult", "ToolContext", "ToolWrapper", "ToolNotPermitted",
    "register", "get_tool", "known_tools", "resolve_tool",
]
