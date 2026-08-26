"""Worker context building: upstream findings -> inputs/input file."""

import asyncio
import os

import pytest

from common.testing import FakePool, make_test_settings
from common.events import TaskMessage
from worker.main import Worker
from worker.tools.base import ToolExecutionError
from worker.tools.registry import resolve_tool

from _helpers import _ctx


@pytest.fixture
def worker(monkeypatch):
    """Worker instance with fakes; no network, no real settings source."""
    from worker.main import Worker

    monkeypatch.setenv("WORKER_CAPABILITIES", "builtin.noop,dnsx,nuclei")
    monkeypatch.setattr("worker.main.load_settings",
                        lambda: make_test_settings())
    w = Worker()
    w.pool = FakePool()
    return w


class TestBuildContext:
    def test_input_file_written_and_deduped(self, worker, tmp_path, monkeypatch):
        async def fake_values(pool, scan_id, types):
            assert types == ["subdomain"]
            return {"subdomain": ["b.com", "a.com", "b.com"]}

        monkeypatch.setattr("worker.main.database.scan_finding_values",
                            fake_values)
        tool = resolve_tool("dnsx", ["dnsx"])
        ctx = asyncio.run(worker._build_context(
            tool,
            _ctx_msg(),
            str(tmp_path),
        ))
        assert ctx.input_file and os.path.isfile(ctx.input_file)
        content = open(ctx.input_file, encoding="utf-8").read()
        assert content == "b.com\na.com"          # deduped, insertion order kept
        assert ctx.inputs["subdomain"] == ["b.com", "a.com", "b.com"]

    def test_no_file_when_not_needed(self, worker, tmp_path):
        tool = resolve_tool("subfinder", ["subfinder"])
        ctx = asyncio.run(worker._build_context(tool, _ctx_msg(), str(tmp_path)))
        assert ctx.input_file is None
        assert ctx.inputs == {}

    def test_empty_consumed_types_fail_fast(self, worker, tmp_path,
                                            monkeypatch):
        """No upstream data => non-retryable dead-letter, no wasted run."""
        async def fake_values(pool, scan_id, types):
            return {"subdomain": []}

        monkeypatch.setattr("worker.main.database.scan_finding_values",
                            fake_values)
        tool = resolve_tool("dnsx", ["dnsx"])
        with pytest.raises(ToolExecutionError):
            asyncio.run(worker._build_context(tool, _ctx_msg(), str(tmp_path)))


class TestParamValidationDeadLetter:
    def test_unknown_param_raises_non_retryable(self, tmp_path):
        tool = resolve_tool("nuclei", ["nuclei"])
        bad = _ctx(tmp_path, params={"severity": "high", "shell": "true"})
        with pytest.raises(ToolExecutionError) as exc:
            tool.build_argv(bad)
        assert "unknown params" in str(exc.value)


def _ctx_msg():
    """Minimal TaskMessage for context tests."""
    from common.events import TaskMessage

    return TaskMessage.model_validate({
        "task_id": "task-1", "idempotency_key": "k", "scan_id": "s1",
        "program_id": "p1", "step_name": "resolve_dns", "tool": "dnsx",
        "target": "example.com", "params": {}, "attempt": 1,
        "max_attempts": 3, "issued_at_epoch": 0.0,
    })
