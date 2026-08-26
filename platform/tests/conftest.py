import os
import sys
from pathlib import Path

# Make `common` / `master` / `worker` importable when running pytest locally.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from common.testing import FakePool, FakeQueue, make_test_settings  # noqa: E402

from master import api as master_api  # noqa: E402

WORKFLOWS_DIR = str(Path(__file__).resolve().parent.parent / "workflows")
API_HDR = {"X-API-Token": "test-token"}


@pytest.fixture
def api_client(monkeypatch):
    """Master app wired to fakes; lifespan never runs (no real connections)."""
    settings = make_test_settings(workflows_dir=WORKFLOWS_DIR)
    pool = FakePool()
    queue = FakeQueue()
    master_api.STATE.update(settings=settings, pool=pool, queue=queue)
    counter = {"n": 0}

    async def fake_get_program(pool, name):
        if name == "demo":
            return {"id": "11111111-1111-1111-1111-111111111111",
                    "name": "demo", "enabled": True}
        return None

    async def fake_scope_rows(pool, program_id):
        return [("example.com", True), ("admin.example.com", False)]

    async def fake_insert_scan(pool, program_id, workflow, requested_by):
        return "scan-00000000"

    async def fake_insert_task(pool, **kwargs):
        counter["n"] += 1
        return f"task-{counter['n']:08d}"

    monkeypatch.setattr(master_api.database, "get_program_by_name", fake_get_program)
    monkeypatch.setattr(master_api.database, "get_scope_rows", fake_scope_rows)
    monkeypatch.setattr(master_api.database, "insert_scan", fake_insert_scan)
    monkeypatch.setattr(master_api.database, "insert_task", fake_insert_task)

    return TestClient(master_api.app)


@pytest.fixture
def api_pool(api_client):
    return master_api.STATE["pool"]


@pytest.fixture
def api_queue(api_client):
    return master_api.STATE["queue"]


@pytest.fixture
def client(api_client):
    """Alias kept for the original test-suite call signature."""
    return api_client
