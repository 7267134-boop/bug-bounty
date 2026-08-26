"""Master API integration tests using FastAPI TestClient + fakes (no PG/Redis).

The `api_client` / `api_pool` / `api_queue` fixtures and `API_HDR` live in
conftest.py so the Stage-1-fix regression tests share the same wiring.
"""

import pytest

from master import api as master_api

from conftest import API_HDR  # noqa: F401  (re-exported for readability)

HDR = API_HDR

class TestAuthAndHealth:
    def test_healthz_open(self, client):
        assert client.get("/healthz").status_code == 200

    def test_readyz_reports_components(self, client):
        body = client.get("/readyz").json()
        assert body["postgres"] is True and body["redis"] is True

    def test_dashboard_html_public(self, client):
        res = client.get("/")
        assert res.status_code == 200
        assert "Bug Bounty Automation Platform" in res.text

    @pytest.mark.parametrize("path", [
        "/api/v1/scans", "/api/v1/workflows", "/metrics",
        "/api/v1/dashboard",
    ])
    def test_protected_routes_require_token(self, client, path):
        assert client.get(path).status_code == 401

class TestScanSubmission:
    def _post(self, client, targets, workflow="smoke"):
        return client.post("/api/v1/scans", headers=HDR, json={
            "program": "demo", "workflow": workflow,
            "targets": targets, "requested_by": "tester",
        })

    def test_unknown_program_rejected(self, client):
        res = client.post("/api/v1/scans", headers=HDR, json={
            "program": "ghost", "workflow": "smoke",
            "targets": ["example.com"], "requested_by": "tester"})
        assert res.status_code == 403

    def test_all_out_of_scope_blocked(self, client):
        res = self._post(client, ["evil.net", "admin.example.com"])
        assert res.status_code == 403
        detail = res.json()["detail"]
        decisions = {d["target"]: d["allowed"] for d in detail["decisions"]}
        assert decisions["admin.example.com"] is False   # deny-wins
        assert decisions["evil.net"] is False            # default-deny

    def test_invalid_target_structurally_rejected(self, client):
        res = self._post(client, ["bad; rm -rf /"])
        assert res.status_code == 403
        decisions = res.json()["detail"]["decisions"]
        assert "forbidden characters" in decisions[0]["reason"]

    def test_smoke_scan_enqueues_only_root_tasks(self, client):
        res = self._post(client, ["example.com"])
        assert res.status_code == 201
        body = res.json()
        # smoke = per_target echo + once summary(depends) -> 1 root task
        assert body["tasks_enqueued"] == 1
        queue = master_api.STATE["queue"]
        assert len(queue.enqueued_payloads) == 1
        msg = queue.enqueued_payloads[0]
        assert msg["tool"] == "builtin.noop"
        assert msg["target"] == "example.com"

    def test_recon_workflow_fans_out_with_deps(self, client):
        res = self._post(client, ["example.com", "two.example.com"],
                         workflow="recon")
        assert res.status_code == 201
        queue = master_api.STATE["queue"]
        tools_sent = sorted(p["tool"] for p in queue.enqueued_payloads)
        # only dependency-free steps dispatched initially: enum x2 targets
        assert tools_sent == ["assetfinder", "assetfinder",
                              "subfinder", "subfinder"]
        assert all(p["attempt"] == 1 for p in queue.enqueued_payloads)

    def test_unknown_workflow_400(self, client):
        assert self._post(client, ["example.com"],
                          workflow="does-not-exist").status_code == 400

class TestStatusAndMetrics:
    def test_scan_status_404(self, client):
        master_api.STATE["pool"].canned["where id = $1::uuid"] = []
        assert client.get("/api/v1/scans/nope",
                          headers=HDR).status_code == 404

    def test_metrics_shape(self, client):
        data = client.get("/metrics", headers=HDR).json()
        snap = data["snapshot"]
        assert {"scans", "tasks", "workers_alive",
                "findings_total", "findings_new"} <= set(snap)
        assert "bb_workers_alive" in data["prometheus"]

    def test_dashboard_endpoint_single_roundtrip(self, client):
        pool = master_api.STATE["pool"]
        pool.canned["from scans s"] = [
            {"scan_id": "abc", "status": "completed", "workflow": "smoke",
             "created_at": "now", "requested_by": "tester",
             "task_states": {"succeeded": 2}},
        ]
        pool.canned["from findings"] = 7
        data = client.get("/api/v1/dashboard", headers=HDR).json()
        assert data["scans"][0]["scan_id"] == "abc"
        assert "workers_alive" in data["metrics"]
        assert data["metrics"]["findings_total"] == 7

    def test_dashboard_includes_severity_and_events(self, client):
        pool = master_api.STATE["pool"]
        pool.canned["group by severity"] = [{"severity": "high", "n": 4}]
        pool.canned["from audit_log"] = [
            {"ts": "2026-08-25T00:00:00Z", "actor": "master",
             "action": "scan.accepted", "subject": "scan-1",
             "decision": "allow"},
        ]
        data = client.get("/api/v1/dashboard", headers=HDR).json()
        assert data["severity"]["high"] == 4          # triage backlog histogram
        assert data["events"][0]["action"] == "scan.accepted"

    def test_workers_endpoint_requires_token_and_lists_fleet(self, client):
        assert client.get("/api/v1/workers").status_code == 401
        pool = master_api.STATE["pool"]
        pool.canned["from worker_heartbeats"] = [
            {"worker_id": "w1", "capabilities": ["subfinder"],
             "last_seen": "2026-08-25T00:00:00Z"},
        ]
        data = client.get("/api/v1/workers", headers=HDR).json()
        assert data["workers"][0]["worker_id"] == "w1"
        assert data["workers"][0]["capabilities"] == ["subfinder"]

    def test_list_scans_limit_clamped(self, client):
        res = client.get("/api/v1/scans?limit=99999", headers=HDR)
        assert res.status_code == 200 and "scans" in res.json()


class TestRecordFindingsBatch:
    def test_batched_write_counts_new_entities(self):
        import asyncio

        from common.db import record_findings
        from common.testing import FakePool

        async def run():
            pool = FakePool()   # no fingerprints seen before
            recorded, new = await record_findings(
                pool, program_id="p1", scan_id="s1", task_id="t1",
                target="example.com",
                findings=[
                    {"type": "subdomain", "subdomain": "a.example.com"},
                    {"type": "subdomain", "subdomain": "b.example.com"},
                    {"type": "subdomain", "subdomain": "a.example.com"},  # dup
                    {"type": "garbage"},                                   # skipped
                ],
            )
            return pool, recorded, new

        pool, recorded, new = asyncio.run(run())
        assert (recorded, new) == (2, 2)          # dedup within batch
        # single transaction + single executemany batch (perf invariant)
        assert pool.transactions == 1
        assert len(pool.executemany_calls) == 1
        assert pool.executemany_calls[0][1] == 2



