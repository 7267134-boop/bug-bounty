"""Tests for research-driven upgrades: deps, fingerprints, rate limiting."""

import asyncio

import pytest

from common.ids import entity_fingerprint, idempotency_key
from common.ratelimit import TokenBucket


WORKFLOWS_DIR = None  # keep namespace tidy


class TestEntityFingerprint:
    def test_stable_and_case_insensitive(self):
        a = entity_fingerprint("prog-1", "subdomain", "API.Example.com")
        b = entity_fingerprint("prog-1", "SUBDOMAIN", "api.example.com ")
        assert a == b and len(a) == 64

    def test_differs_across_programs_and_types(self):
        base = entity_fingerprint("p1", "subdomain", "x.com")
        assert entity_fingerprint("p2", "subdomain", "x.com") != base
        assert entity_fingerprint("p1", "live_host", "x.com") != base

    def test_idempotency_key_unchanged_contract(self):
        k1 = idempotency_key("scan", "step", {"b": 1, "a": 2})
        k2 = idempotency_key("scan", "step", {"a": 2, "b": 1})
        assert k1 == k2


class TestTokenBucket:
    def test_burst_then_throttle(self):
        async def scenario():
            bucket = TokenBucket(rate=50.0, capacity=1.0)
            t0 = asyncio.get_event_loop().time()
            await bucket.acquire()                       # instant (burst token)
            await bucket.acquire()                       # ~1/50s wait
            elapsed = asyncio.get_event_loop().time() - t0
            return elapsed

        elapsed = asyncio.run(scenario())
        assert 0.0 <= elapsed < 0.5                      # throttled but fast

    def test_invalid_rate_rejected(self):
        with pytest.raises(ValueError):
            TokenBucket(rate=0)


class TestWorkflowDependencies:
    def _load(self, tmp_path, body: str):
        from master.orchestrator import WorkflowError, load_workflow

        p = tmp_path / "wf.yaml"
        p.write_text(body, encoding="utf-8")
        return load_workflow(p)

    def test_valid_dependency_chain(self, tmp_path):
        wf = self._load(tmp_path, (
            "name: deps\n"
            "steps:\n"
            "  - name: first\n    tool: builtin.noop\n"
            "  - name: second\n    tool: builtin.noop\n    depends_on: [first]\n"
        ))
        planned = __import__("master.orchestrator", fromlist=["plan_tasks"]) \
            .plan_tasks("scan-x", "prog-x", wf, ["t.com"])
        second = [t for t in planned if t["step_name"] == "second"]
        assert all(t["depends_on"] == ["first"] for t in second)

    def test_unknown_dependency_rejected(self, tmp_path):
        from master.orchestrator import WorkflowError

        with pytest.raises(WorkflowError):
            self._load(tmp_path, (
                "name: bad\nsteps:\n"
                "  - name: s\n    tool: builtin.noop\n    depends_on: [ghost]\n"
            ))

    def test_cycle_rejected(self, tmp_path):
        from master.orchestrator import WorkflowError

        with pytest.raises(WorkflowError) as exc:
            self._load(tmp_path, (
                "name: cyc\nsteps:\n"
                "  - name: alpha\n    tool: builtin.noop\n    depends_on: [beta]\n"
                "  - name: beta\n    tool: builtin.noop\n    depends_on: [alpha]\n"
            ))
        assert "cycle" in str(exc.value)

    def test_smoke_yaml_still_valid(self):
        from master.orchestrator import load_workflow
        from pathlib import Path

        path = Path(__file__).resolve().parent.parent / "workflows" / "smoke.yaml"
        wf = load_workflow(path)
        assert any(s["name"] == "summary_echo" for s in wf["steps"])


class TestNotifications:
    def test_no_webhook_configured_is_graceful(self, monkeypatch):
        from common.notifications import notify_event

        monkeypatch.delenv("WEBHOOK_URL", raising=False)
        assert asyncio.run(notify_event("test.event", {"k": "v"})) is False
