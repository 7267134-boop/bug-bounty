"""Pillar B (human triage) + Pillar A (algorithmic routing gates) tests."""

import pytest

from common import db as database
from master import api as master_api
from master.orchestrator import WorkflowError, load_workflow

from pathlib import Path

from conftest import API_HDR as HDR

WORKFLOWS = Path(__file__).resolve().parent.parent / "workflows"


class TestTriageEndpoints:
    def test_findings_listing_requires_token(self, api_client):
        assert api_client.get("/api/v1/findings").status_code == 401

    def test_findings_listing_returns_rows(self, api_client, monkeypatch):
        rows = [{"id": "f1", "type": "vulnerability",
                 "value": "dalfox-xss@https://x.com/?q=1",
                 "severity": "high", "validation_state": "unvalidated",
                 "is_new": True}]

        async def fake_list(pool, **kw):
            assert kw["state"] == "unvalidated"
            return rows

        monkeypatch.setattr(master_api.database, "list_findings", fake_list)
        res = api_client.get(
            "/api/v1/findings?state=unvalidated&limit=10", headers=HDR)
        assert res.status_code == 200
        assert res.json()["findings"][0]["id"] == "f1"

    def test_triage_validated_updates_and_audits(self, api_client, monkeypatch):
        captured = {}

        async def fake_triage(pool, finding_id, decision, actor):
            captured.update(id=finding_id, decision=decision, actor=actor)
            return {"id": finding_id, "fingerprint": "fp", "type": "vulnerability",
                    "value": "x@y", "validation_state": decision}

        audits = []

        async def fake_audit(pool, **kw):
            audits.append(kw)

        monkeypatch.setattr(master_api.database, "triage_finding", fake_triage)
        monkeypatch.setattr(master_api.database, "audit_event", fake_audit)

        res = api_client.patch("/api/v1/findings/f-9/triage", headers=HDR,
                               json={"decision": "validated",
                                     "requested_by": "analyst",
                                     "note": "confirmed manually"})
        assert res.status_code == 200
        assert captured["decision"] == "validated"
        assert captured["actor"] == "human:analyst"
        assert audits[0]["action"] == "finding.triage"
        assert audits[0]["details"]["decision"] == "validated"

    def test_triage_refuted_allowed(self, api_client, monkeypatch):
        async def fake_triage(pool, finding_id, decision, actor):
            return {"id": finding_id, "validation_state": decision,
                    "fingerprint": "fp", "type": "vulnerability",
                    "value": "x@y"}
        monkeypatch.setattr(master_api.database, "triage_finding", fake_triage)
        res = api_client.patch("/api/v1/findings/f-1/triage", headers=HDR,
                               json={"decision": "refuted",
                                     "requested_by": "analyst"})
        assert res.status_code == 200
        assert res.json()["finding"]["validation_state"] == "refuted"

    def test_triage_invalid_decision_422(self, api_client):
        res = api_client.patch("/api/v1/findings/f-1/triage", headers=HDR,
                               json={"decision": "maybe-fine",
                                     "requested_by": "analyst"})
        assert res.status_code == 422   # only validated|refuted exist

    def test_triage_unknown_finding_404(self, api_client, monkeypatch):
        async def none_triage(pool, fid, decision, actor):
            return None
        monkeypatch.setattr(master_api.database, "triage_finding", none_triage)
        res = api_client.patch("/api/v1/findings/nope/triage", headers=HDR,
                               json={"decision": "validated",
                                     "requested_by": "analyst"})
        assert res.status_code == 404

class TestRoutingGates:
    def _load(self, body: str, name="routed.yaml"):
        p = WORKFLOWS / name
        p.write_text(body, encoding="utf-8")
        try:
            return load_workflow(p)
        finally:
            p.unlink(missing_ok=True)

    def test_when_gate_validated_and_planned(self):
        from master.orchestrator import plan_tasks
        wf = self._load(
            "name: routed\nsteps:\n"
            "  - name: recon\n    tool: builtin.noop\n"
            "  - name: deep\n    tool: builtin.noop\n"
            "    depends_on: [recon]\n"
            "    when:\n      has_finding_type: open_port\n"
        )
        planned = plan_tasks("s", "p", wf, ["t.com"])
        deep = [t for t in planned if t["step_name"] == "deep"]
        assert all(t["when_finding_type"] == "open_port" for t in deep)

    def test_invalid_when_shape_rejected(self):
        with pytest.raises(WorkflowError):
            self._load(
                "name: bad\nsteps:\n"
                "  - name: s1\n    tool: builtin.noop\n"
                "    when:\n      runs_if: something\n"
            )

    def test_unknown_finding_type_chars_rejected(self):
        with pytest.raises(WorkflowError):
            self._load(
                "name: bad\nsteps:\n"
                "  - name: s1\n    tool: builtin.noop\n"
                "    when:\n      has_finding_type: 'drop table'\n"
            )

    def test_dispatcher_sql_contains_gate(self):
        sql = database._READY_TASKS_SQL.lower()
        assert "when_finding_type is null" in sql
        assert "from findings f" in sql

    def test_submission_persists_gate_and_holds_dispatch(self, api_client,
                                                         monkeypatch):
        seen_kwargs: list[dict] = []

        async def spy_insert(pool, **kwargs):
            seen_kwargs.append(kwargs)
            return f"task-{len(seen_kwargs)}"

        async def noop(*a, **k):
            return None

        monkeypatch.setattr(master_api.database, "insert_task", spy_insert)
        monkeypatch.setattr(master_api.database, "mark_dispatched", noop)

        wf_path = WORKFLOWS / "_gate_test.yaml"
        wf_path.write_text(
            "name: gatetest\nsteps:\n"
            "  - name: base\n    tool: builtin.noop\n"
            "  - name: gated\n    tool: dalfox\n"
            "    depends_on: [base]\n"
            "    when:\n      has_finding_type: url_param\n",
            encoding="utf-8")
        try:
            res = api_client.post("/api/v1/scans", headers=HDR, json={
                "program": "demo", "workflow": "_gate_test",
                "targets": ["example.com"], "requested_by": "tester"})
        finally:
            wf_path.unlink(missing_ok=True)

        assert res.status_code == 201
        gated = [k for k in seen_kwargs if k["step_name"] == "gated"]
        assert gated and gated[0]["when_finding_type"] == "url_param"
        # gated task must NOT be dispatched on submission (waits for findings)
        queue = master_api.STATE["queue"]
        assert all(p["tool"] != "dalfox" for p in queue.enqueued_payloads)



