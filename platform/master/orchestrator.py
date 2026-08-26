"""Workflow loading, validation, and task planning (Osmedeus-style YAML).

Stage 1 ships the schema, loader and planner. The smoke workflow exercises
the pipeline end to end with ``builtin.noop``. Later stages add real tools by
(1) registering wrappers on the worker, (2) adding the tool name here.
"""

from __future__ import annotations

import logging
import pathlib
import re
from typing import Any

import yaml

from common.ids import idempotency_key

log = logging.getLogger("master.workflows")

# Tools the MASTER is allowed to plan. The worker enforces its own capability
# allowlist; this list prevents misconfigured workers from being handed
# unregistered tool names via workflow files.
ALLOWED_TOOLS = {
    "builtin.noop",
    # -- Stage 2: recon toolchain --
    "subfinder", "assetfinder", "amass",
    "massdns",                       # dead-domain filter (routing gate)
    "dnsx", "httpx", "naabu",
    "nmap",                          # targeted -sV -sC on naabu results
    "waybackurls", "katana", "nuclei", "uncover",
    # -- Stage 3: decision-engine routed tools --
    "routing.bypass403", "wpscan", "corsy",
    # -- Stage 4: focused scanning --
    "ffuf", "arjun", "sqlmap", "trufflehog",
    # -- Stage 4: focused scanning / visual recon / OOB --
    "dalfox", "gowitness", "interactsh",
}
STAGE1_ALLOWED_TOOLS = ALLOWED_TOOLS  # backward-compat alias

_WORKFLOW_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{2,48}$")
_STEP_NAME_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,64}$")
_FANOUT_MODES = {"per_target", "once"}
_ALLOWED_KEYS = {"name", "description", "version", "defaults", "steps"}


class WorkflowError(ValueError):
    pass


def load_workflow(path: pathlib.Path) -> dict[str, Any]:
    """Parse + strictly validate one workflow YAML file."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise WorkflowError(f"workflow not found: {path.name}") from exc
    except OSError as exc:
        raise WorkflowError(f"{path.name}: unreadable: {exc}") from exc
    except yaml.YAMLError as exc:
        raise WorkflowError(f"{path.name}: invalid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise WorkflowError(f"{path.name}: top level must be a mapping")

    unknown = set(raw) - _ALLOWED_KEYS
    if unknown:
        raise WorkflowError(f"{path.name}: unknown top-level keys {sorted(unknown)}")
    if not _WORKFLOW_NAME_RE.match(str(raw.get("name", ""))):
        raise WorkflowError(f"{path.name}: illegal workflow name")
    steps = raw.get("steps")
    if not isinstance(steps, list) or not steps:
        raise WorkflowError(f"{path.name}: 'steps' must be a non-empty list")

    defaults = raw.get("defaults") or {}
    if not isinstance(defaults, dict):
        raise WorkflowError(f"{path.name}: 'defaults' must be a mapping")
    max_attempts = int(defaults.get("max_attempts", 3))
    if not 1 <= max_attempts <= 10:
        raise WorkflowError(f"{path.name}: defaults.max_attempts out of range 1..10")

    def _validate_when(when: Any, sname: str) -> str | None:
        """Validate a routing gate: {'has_finding_type': <type>}."""
        if when is None:
            return None
        if not isinstance(when, dict) or set(when) != {"has_finding_type"}:
            raise WorkflowError(
                f"{path.name}: step {sname!r} 'when' must be "
                "{'has_finding_type': <type>}"
            )
        ftype = str(when["has_finding_type"]).strip().lower()
        if not re.match(r"^[a-z0-9_]{2,32}$", ftype):
            raise WorkflowError(
                f"{path.name}: step {sname!r} has_finding_type illegal: {ftype!r}"
            )
        return ftype

    seen_names: set[str] = set()
    for step in steps:
        if not isinstance(step, dict):
            raise WorkflowError(f"{path.name}: each step must be a mapping")
        unknown = set(step) - {"name", "tool", "fanout", "params",
                               "depends_on", "when"}
        if unknown:
            raise WorkflowError(f"{path.name}: unknown step keys {sorted(unknown)}")
        sname = str(step.get("name", ""))
        tool = str(step.get("tool", ""))
        if not _STEP_NAME_RE.match(sname):
            raise WorkflowError(f"{path.name}: illegal step name {sname!r}")
        if sname in seen_names:
            raise WorkflowError(f"{path.name}: duplicate step name {sname!r}")
        seen_names.add(sname)

    # ---- cross-step validation (all names known) ----
    by_name = {str(s["name"]): s for s in steps}
    for sname, step in by_name.items():
        tool = str(step.get("tool", ""))
        if tool not in ALLOWED_TOOLS:
            raise WorkflowError(
                f"{path.name}: tool {tool!r} is not allowed in this stage "
                f"(allowed: {sorted(ALLOWED_TOOLS)})"
            )
        fanout = step.get("fanout", "per_target")
        if fanout not in _FANOUT_MODES:
            raise WorkflowError(
                f"{path.name}: fanout must be one of {sorted(_FANOUT_MODES)}"
            )
        params = step.get("params") or {}
        if not isinstance(params, dict):
            raise WorkflowError(f"{path.name}: step {sname!r} params must be a mapping")
        deps = list(step.get("depends_on") or [])
        for dep in deps:
            if dep not in by_name:
                raise WorkflowError(
                    f"{path.name}: step {sname!r} depends on unknown step {dep!r}"
                )
        when = step.get("when")
        if when is not None:
            gate = _validate_when(when, sname)
            step["when"] = {"has_finding_type": gate}
    _assert_acyclic(by_name, path.name)

    raw.setdefault("version", 1)
    raw["defaults"] = {"max_attempts": max_attempts}
    return raw


def _assert_acyclic(steps_by_name: dict[str, dict], filename: str) -> None:
    graph = {n: list(s.get("depends_on") or []) for n, s in steps_by_name.items()}
    state: dict[str, int] = {}  # 0=unvisited 1=in-stack 2=done

    def visit(node: str) -> None:
        if state.get(node) == 1:
            raise WorkflowError(f"{filename}: dependency cycle involving {node!r}")
        if state.get(node) == 2:
            return
        state[node] = 1
        for dep in graph.get(node, []):
            visit(dep)
        state[node] = 2

    for name in graph:
        visit(name)


def available_workflows(workflows_dir: str | pathlib.Path) -> list[str]:
    directory = pathlib.Path(workflows_dir)
    return sorted(p.stem for p in directory.glob("*.yaml"))


def plan_tasks(scan_id: str, program_id: str, workflow: dict[str, Any],
               targets: list[str]) -> list[dict[str, Any]]:
    """Expand a validated workflow x targets into idempotent task dicts."""
    planned: list[dict[str, Any]] = []
    max_attempts = int(workflow.get("defaults", {}).get("max_attempts", 3))
    for step in workflow["steps"]:
        # 'once' steps receive all targets in a single task; 'per_target'
        # (the default) fans out into one task per target.
        if step.get("fanout") == "once":
            groups: list[list[str]] = [list(targets)]
        else:
            groups = [[t] for t in targets]
        for group in groups:
            params = dict(step.get("params") or {})
            if step.get("fanout") == "once":
                params["targets"] = list(group)
                group_repr = ",".join(sorted(group))
            else:
                group_repr = group[0]
            key = idempotency_key(scan_id, step["name"], step["tool"], group_repr,
                                  params)
            planned.append({
                "step_name": step["name"],
                "tool": step["tool"],
                "target": group_repr,
                "params": params,
                "idempotency_key": key,
                "max_attempts": max_attempts,
                "depends_on": [str(d) for d in (step.get("depends_on") or [])],
                "when_finding_type": (step.get("when") or {}).get("has_finding_type"),
            })
    log.info("workflow planned", extra={
        "scan_id": scan_id, "workflow": workflow["name"], "tasks": len(planned),
    })
    return planned
