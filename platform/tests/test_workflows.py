"""Tests for the workflow loader/planner and the tool registry gates."""

from pathlib import Path

import pytest

from common.events import TaskMessage
from master.orchestrator import WorkflowError, load_workflow, plan_tasks
from worker.tools.base import ToolNotPermitted
from worker.tools.registry import known_tools, register, resolve_tool
import worker.tools.registry  # noqa: F401 - ensures builtin.noop is registered


WORKFLOWS_DIR = Path(__file__).resolve().parent.parent / "workflows"


class TestWorkflowLoader:
    def test_smoke_workflow_is_valid(self):
        wf = load_workflow(WORKFLOWS_DIR / "smoke.yaml")
        assert wf["name"] == "smoke"
        assert wf["steps"][0]["tool"] == "builtin.noop"

    def test_passive_preset_is_truly_passive(self):
        """reNgine-style 'Passive Scan Engine' preset: zero intrusive steps."""
        wf = load_workflow(WORKFLOWS_DIR / "passive.yaml")
        tools = {s["tool"] for s in wf["steps"]}
        assert tools <= {"subfinder", "assetfinder", "massdns", "httpx"}
        # no active scanning/exploitation may ever appear in this preset
        assert not tools & {"nuclei", "dalfox", "sqlmap", "nmap", "naabu",
                            "ffuf", "arjun", "wpscan"}

    def test_unknown_tool_rejected(self, tmp_path: Path):
        p = tmp_path / "bad.yaml"
        p.write_text(
            "name: bad\nsteps:\n  - name: s\n    tool: nuclei\n", encoding="utf-8"
        )
        with pytest.raises(WorkflowError):
            load_workflow(p)

    def test_bad_top_level_key_rejected(self, tmp_path: Path):
        p = tmp_path / "bad.yaml"
        p.write_text(
            "name: bad\nshell: /bin/bash\nsteps:\n  - name: s\n    tool: builtin.noop\n",
            encoding="utf-8",
        )
        with pytest.raises(WorkflowError):
            load_workflow(p)

    def test_bad_fanout_rejected(self, tmp_path: Path):
        p = tmp_path / "bad.yaml"
        p.write_text(
            "name: bad\nsteps:\n  - name: s\n    tool: builtin.noop\n    fanout: wild\n",
            encoding="utf-8",
        )
        with pytest.raises(WorkflowError):
            load_workflow(p)

    def test_duplicate_step_names_rejected(self, tmp_path: Path):
        p = tmp_path / "bad.yaml"
        p.write_text(
            "name: bad\nsteps:\n"
            "  - name: s\n    tool: builtin.noop\n"
            "  - name: s\n    tool: builtin.noop\n",
            encoding="utf-8",
        )
        with pytest.raises(WorkflowError):
            load_workflow(p)


class TestPlanner:
    def test_per_target_fanout_and_stable_keys(self):
        wf = {
            "name": "smoke",
            "defaults": {"max_attempts": 3},
            "steps": [{"name": "s1", "tool": "builtin.noop", "fanout": "per_target"}],
        }
        tasks = plan_tasks("scan-1", "prog-1", wf, ["a.example.com", "b.example.com"])
        assert len(tasks) == 2
        keys = {t["idempotency_key"] for t in tasks}
        again = plan_tasks("scan-1", "prog-1", wf, ["b.example.com", "a.example.com"])
        assert {t["idempotency_key"] for t in again} == keys  # order-independent

    def test_once_fanout_single_task(self):
        wf = {
            "name": "smoke",
            "defaults": {"max_attempts": 3},
            "steps": [{"name": "all", "tool": "builtin.noop", "fanout": "once"}],
        }
        tasks = plan_tasks("scan-2", "prog-1", wf, ["a.com", "b.com"])
        assert len(tasks) == 1
        assert tasks[0]["params"]["targets"] == ["a.com", "b.com"]


class TestRegistryGates:
    def test_builtin_noop_registered(self):
        assert "builtin.noop" in known_tools()

    def test_capability_gate_fail_closed(self):
        with pytest.raises(ToolNotPermitted):
            resolve_tool("subfinder", ["builtin.noop"])          # not registered
        with pytest.raises(ToolNotPermitted):
            resolve_tool("builtin.noop", [])                     # not in allowlist
        assert resolve_tool("builtin.noop", ["builtin.noop"]) is not None


class TestTaskMessageValidation:
    def test_rejects_injection_in_step_name(self):
        import pytest as _pytest
        from pydantic import ValidationError

        base = dict(task_id="t", idempotency_key="k", scan_id="s", program_id="p",
                    step_name="ok.step-1", tool="builtin.noop", target="a.com")
        assert TaskMessage.model_validate(base).step_name == "ok.step-1"
        bad = dict(base, step_name="x; rm -rf /")
        with _pytest.raises(ValidationError):
            TaskMessage.model_validate(bad)
