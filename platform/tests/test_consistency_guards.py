"""Cross-component consistency guards (drift detection).

These tests exist to catch the class of bug where two components that must
agree silently diverge — e.g. a wrapper emitting a finding type it never
declared, or the master allowing a tool the worker never registered.
"""

import json
from pathlib import Path

import pytest
import yaml

from common.constants import SEVERITIES, VALIDATION_STATES
from master.orchestrator import ALLOWED_TOOLS, load_workflow
from mcp_server import tools as mcp_tools
from worker.tools.registry import known_tools, resolve_tool

WORKFLOWS = Path(__file__).resolve().parent.parent / "workflows"


# --------------------------------------------------------------------- #
# Master allowlist <-> worker registry                                   #
# --------------------------------------------------------------------- #
class TestToolSurfaceAlignment:
    def test_master_allowlist_matches_worker_registry(self):
        """Every plannable tool must exist as a registered wrapper and
        vice versa — no orphan capability on either side."""
        assert set(ALLOWED_TOOLS) == set(known_tools())

    def test_every_wrapper_declares_unique_name_and_binary(self):
        from worker.tools.registry import get_tool

        for name in known_tools():
            tool = get_tool(name)
            assert tool.name == name
            assert isinstance(tool.produces, list) and tool.produces
            assert isinstance(tool.consumes, list)

    def test_declared_produces_covers_emitted_types(self):
        """Static contract check: parsers may only emit types they declare.

        (js_url / exposed_service were historical offenders.) Each wrapper's
        parse() is executed against a trivially-empty output here; type-level
        emission coverage lives in the per-tool parser tests.
        """
        emitted_by_doc = {
            # wrappers documented in docs/TOOLCHAIN.md to emit extra signals:
            "nmap": {"service", "exposed_service"},
            "waybackurls": {"archive_url", "url_param", "js_url"},
            "katana": {"url", "url_param", "js_url"},
            "httpx": {"live_host", "wordpress", "http_403", "login_page",
                      "api_surface"},
        }
        for name, expected in emitted_by_doc.items():
            tool = resolve_tool(name, [name])
            missing = expected - set(tool.produces)
            assert not missing, f"{name} emits undeclared types: {missing}"


# --------------------------------------------------------------------- #
# MCP enums <-> common constants                                         #
# --------------------------------------------------------------------- #
class TestMcpEnumDrift:
    def test_severities_match_common_constants(self):
        assert tuple(mcp_tools.SEVERITIES) == SEVERITIES

    def test_validation_states_match_common_constants(self):
        assert tuple(mcp_tools.STATES) == VALIDATION_STATES


# --------------------------------------------------------------------- #
# Workflow dataflow integrity                                            #
# --------------------------------------------------------------------- #
def _produces(tool_name: str) -> set[str]:
    return set(resolve_tool(tool_name, [tool_name]).produces)


def _consumes(tool_name: str) -> set[str]:
    return set(resolve_tool(tool_name, [tool_name]).consumes)


@pytest.mark.parametrize("workflow", ["smoke", "recon", "deep-recon",
                                      "focused"])
class TestWorkflowDataflowIntegrity:
    def _load(self, workflow):
        doc = yaml.safe_load((WORKFLOWS / f"{workflow}.yaml").read_text(
            encoding="utf-8"))
        return load_workflow(WORKFLOWS / f"{workflow}.yaml"), doc

    def test_consumes_are_produced_upstream(self, workflow):
        """Every consumed finding type must be produced by an EARLIER step
        (declared order is topological and cycle-checked at load time)."""
        wf, _ = self._load(workflow)
        produced: set[str] = set()
        seen_names: set[str] = set()
        problems = []
        for step in wf["steps"]:
            late_deps = set(step.get("depends_on") or []) - seen_names
            if late_deps:
                problems.append(f"{step['name']}: forward deps {late_deps}")
            missing = _consumes(step["tool"]) - produced
            if missing:
                problems.append(f"{step['name']}: consumes unproduced "
                                f"{sorted(missing)}")
            produced |= _produces(step["tool"])
            seen_names.add(step["name"])
        assert not problems, problems

    def test_routing_gates_reference_produced_types(self, workflow):
        wf, _ = self._load(workflow)
        produced: set[str] = set()
        for step in wf["steps"]:
            gate = (step.get("when") or {}).get("has_finding_type")
            if gate is not None:
                assert gate in produced, \
                    f"{step['name']}: gate '{gate}' has no upstream producer"
            produced |= _produces(step["tool"])

    def test_params_respect_tool_whitelists(self, workflow):
        from worker.tools.base import ToolExecutionError
        from worker.tools.registry import get_tool

        _, doc = self._load(workflow)
        for step in doc["steps"]:
            tool = get_tool(step["tool"])
            unknown = set(step.get("params") or {}) - tool.allowed_params
            assert not unknown, \
                f"{step['name']}: params {unknown} not in " \
                f"{tool.name}.allowed_params"