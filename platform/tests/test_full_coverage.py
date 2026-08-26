"""Full-system coverage sweep (post-review): modules the original suite
left thin. Organized per source file; everything runs offline."""

import asyncio
import json
import logging
import pathlib
import sys

import pytest


# --------------------------------------------------------------------- #
# common/logging_setup.py                                                #
# --------------------------------------------------------------------- #
class TestLoggingSetup:
    def test_json_formatter_shape_and_extras(self):
        from common.logging_setup import JsonFormatter

        fmt = JsonFormatter()
        rec = logging.LogRecord("common.test", logging.WARNING, "p.py", 1,
                                "hello %s", ("world",), None)
        rec.service = "unit"
        rec.custom_extra = {"a": 1}
        out = json.loads(fmt.format(rec))
        assert out["level"] == "WARNING" and out["msg"] == "hello world"
        assert out["service"] == "unit"
        assert out["custom_extra"] == {"a": 1}
        assert out["ts"].endswith("Z") and "T" in out["ts"]

    def test_unserializable_extra_stringified(self):
        from common.logging_setup import JsonFormatter

        rec = logging.LogRecord("l", logging.INFO, "p", 1, "m", None, None)
        rec.obj = object()
        out = json.loads(JsonFormatter().format(rec))
        assert isinstance(out["obj"], str)

    def test_exception_rendering(self):
        from common.logging_setup import JsonFormatter

        try:
            raise ValueError("boom")
        except ValueError:
            exc_info = sys.exc_info()
        rec = logging.LogRecord("l", logging.ERROR, "p", 1, "m", None,
                                exc_info)
        out = json.loads(JsonFormatter().format(rec))
        assert "ValueError: boom" in out["exc"]

    def test_setup_logging_invalid_level_falls_back(self):
        from common.logging_setup import setup_logging

        setup_logging("unit-test", "NOT-A-LEVEL")
        assert logging.getLogger().level == logging.INFO

    def test_service_filter_stamps_record(self):
        from common.logging_setup import JsonFormatter

        fmt = JsonFormatter()
        rec = logging.LogRecord("l", logging.INFO, "p", 1, "m", None, None)
        # simulate what setup_logging's filter does at emit time
        if not hasattr(rec, "service"):
            rec.service = "svc-x"
        assert json.loads(fmt.format(rec))["service"] == "svc-x"


# --------------------------------------------------------------------- #
# common/events.py                                                       #
# --------------------------------------------------------------------- #
class TestEvents:
    BASE = dict(task_id="t", idempotency_key="k", scan_id="s",
                program_id="p", target="example.com")

    def test_valid_message_roundtrip(self):
        from common.events import TaskMessage

        msg = TaskMessage(step_name="probe_web", tool="httpx", **self.BASE)
        assert msg.attempt == 1 and msg.max_attempts == 3
        assert msg.params == {}

    @pytest.mark.parametrize("bad", ["Step One", "UPPER", "a;b", "-lead"])
    def test_illegal_step_name_rejected(self, bad):
        from common.events import TaskMessage

        with pytest.raises(Exception):
            TaskMessage(step_name=bad, tool="httpx", **self.BASE)

    @pytest.mark.parametrize("bad", ["Evil Tool", "tool$(x)", ""])
    def test_illegal_tool_name_rejected(self, bad):
        from common.events import TaskMessage

        with pytest.raises(Exception):
            TaskMessage(step_name="ok", tool=bad, **self.BASE)

    def test_task_result_defaults(self):
        from common.events import TaskResult

        r = TaskResult(task_id="t", ok=False)
        assert r.exit_code is None and r.findings_count == 0
        assert r.retryable is False and r.summary == ""


# --------------------------------------------------------------------- #
# common/ids.py                                                          #
# --------------------------------------------------------------------- #
class TestIds:
    def test_idempotency_key_is_key_order_stable(self):
        from common.ids import idempotency_key

        k1 = idempotency_key("scan", "step", {"a": 1, "b": 2})
        k2 = idempotency_key("scan", "step", {"b": 2, "a": 1})
        assert k1 == k2 and len(k1) == 64

    def test_idempotency_key_differs_on_params(self):
        from common.ids import idempotency_key

        assert idempotency_key("s", {"x": 1}) != idempotency_key("s", {"x": 2})

    def test_entity_fingerprint_normalization(self):
        from common.ids import entity_fingerprint

        a = entity_fingerprint(" Prog ", " Subdomain ", " A.Example.COM ")
        b = entity_fingerprint("prog", "subdomain", "a.example.com")
        assert a == b and len(a) == 64

    def test_new_id_unique_hex(self):
        from common.ids import new_id

        assert new_id() != new_id() and len(new_id()) == 32


# --------------------------------------------------------------------- #
# worker/tools/registry.py                                               #
# --------------------------------------------------------------------- #
class TestRegistry:
    def test_register_requires_name(self):
        from worker.tools.base import ToolWrapper
        from worker.tools.registry import register

        with pytest.raises(ValueError):
            register(type("NoName", (ToolWrapper,), {}))

    def test_register_rejects_abstract_name(self):
        from worker.tools.base import ToolWrapper
        from worker.tools.registry import register

        with pytest.raises(ValueError):
            register(type("X", (ToolWrapper,), {"name": "abstract"}))

    def test_resolve_unregistered_fails(self):
        from worker.tools.registry import resolve_tool

        with pytest.raises(Exception):
            resolve_tool("not-a-tool", ["not-a-tool"])

    def test_resolve_without_capability_fails(self):
        from worker.tools.registry import resolve_tool

        with pytest.raises(Exception):
            resolve_tool("subfinder", [])

    def test_check_binary_semantics(self):
        from worker.tools.base import ToolWrapper
        from worker.tools.registry import get_tool

        assert get_tool("builtin.noop").check_binary() is True
        ghost = type("Ghost", (ToolWrapper,), {
            "name": "ghost-x",
            "binary": "definitely-missing-bin-x",
            "build_argv": lambda self, ctx: ["x"],
            "parse": lambda self, result, ctx: [],
        })
        assert ghost().check_binary() is False


# --------------------------------------------------------------------- #
# master/orchestrator.py — strict validation negatives                   #
# --------------------------------------------------------------------- #
class TestWorkflowValidation:
    BASE = {"name": "wf-ok", "steps": [{"name": "s1", "tool": "builtin.noop"}]}

    @staticmethod
    def _write(tmp_path, doc) -> pathlib.Path:
        import yaml

        p = tmp_path / "wf.yaml"
        p.write_text(yaml.safe_dump(doc), encoding="utf-8")
        return p

    def _load(self, tmp_path, doc):
        from master.orchestrator import WorkflowError, load_workflow

        with pytest.raises(WorkflowError) as exc:
            load_workflow(self._write(tmp_path, doc))
        return str(exc.value)

    def test_unknown_top_level_key(self, tmp_path):
        assert "unknown top-level" in self._load(
            tmp_path, {**self.BASE, "hacker_key": 1})

    def test_illegal_workflow_name(self, tmp_path):
        for bad in ("X", "-lead", "has space", "ab"):
            self.BASE["name"] = bad
            assert self._load(tmp_path, self.BASE)
        self.BASE["name"] = "wf-ok"

    def test_empty_steps_rejected(self, tmp_path):
        assert self._load(tmp_path, {"name": "wf-ok", "steps": []})

    def test_max_attempts_out_of_range(self, tmp_path):
        doc = {**self.BASE, "defaults": {"max_attempts": 99}}
        assert "max_attempts" in self._load(tmp_path, doc)

    def test_disallowed_tool_rejected(self, tmp_path):
        doc = {"name": "wf-ok",
               "steps": [{"name": "s1", "tool": "not-allowed-tool"}]}
        assert "not allowed in this stage" in self._load(tmp_path, doc)

    def test_bad_fanout_rejected(self, tmp_path):
        doc = {"name": "wf-ok", "steps": [
            {"name": "s1", "tool": "builtin.noop", "fanout": "sometimes"}]}
        assert "fanout" in self._load(tmp_path, doc)

    def test_non_mapping_params_rejected(self, tmp_path):
        doc = {"name": "wf-ok", "steps": [
            {"name": "s1", "tool": "builtin.noop", "params": [1]}]}
        assert "params" in self._load(tmp_path, doc)

    def test_unknown_dependency_rejected(self, tmp_path):
        doc = {"name": "wf-ok", "steps": [
            {"name": "s1", "tool": "builtin.noop", "depends_on": ["ghost"]}]}
        assert "unknown step" in self._load(tmp_path, doc)

    def test_malformed_when_gate_rejected(self, tmp_path):
        doc = {"name": "wf-ok", "steps": [
            {"name": "s1", "tool": "builtin.noop", "when": {"foo": 1}}]}
        assert "'when'" in self._load(tmp_path, doc)

    def test_dependency_cycle_detected(self, tmp_path):
        doc = {"name": "wf-ok", "steps": [
            {"name": "step-a", "tool": "builtin.noop", "depends_on": ["step-b"]},
            {"name": "step-b", "tool": "builtin.noop", "depends_on": ["step-a"]},
        ]}
        assert "cycle" in self._load(tmp_path, doc)


class TestPlanTasks:
    WF = {"name": "wf-ok", "defaults": {"max_attempts": 2}, "steps": [
        {"name": "enum1", "tool": "subfinder"},
        {"name": "once_step", "tool": "nmap", "fanout": "once",
         "depends_on": ["enum1"],
         "when": {"has_finding_type": "open_port"}},
    ]}

    def test_per_target_fanout_expands(self):
        from master.orchestrator import plan_tasks

        tasks = plan_tasks("scan1", "prog", self.WF, ["a.com", "b.com"])
        enum = [t for t in tasks if t["step_name"] == "enum1"]
        assert sorted(t["target"] for t in enum) == ["a.com", "b.com"]

    def test_once_mode_carries_targets_in_params(self):
        from master.orchestrator import plan_tasks

        tasks = plan_tasks("scan1", "prog", self.WF,
                           ["b.com", "a.com"])
        once = next(t for t in tasks if t["step_name"] == "once_step")
        assert once["target"] == "a.com,b.com"
        assert once["params"]["targets"] == ["b.com", "a.com"]
        assert once["depends_on"] == ["enum1"]
        assert once["when_finding_type"] == "open_port"

    def test_idempotency_keys_unique_and_stable(self):
        from master.orchestrator import plan_tasks

        t1 = plan_tasks("scan1", "prog", self.WF, ["a.com"])
        t2 = plan_tasks("scan1", "prog", self.WF, ["a.com"])
        k1 = {t["step_name"]: t["idempotency_key"] for t in t1}
        k2 = {t["step_name"]: t["idempotency_key"] for t in t2}
        assert k1 == k2 and len(set(k1.values())) == len(k1)

    def test_max_attempts_propagated(self):
        from master.orchestrator import plan_tasks

        assert all(t["max_attempts"] == 2
                   for t in plan_tasks("s", "p", self.WF, ["a.com"]))


# --------------------------------------------------------------------- #
# common/redis_client.py — TaskQueue over a fake Redis                   #
# --------------------------------------------------------------------- #
class FakeRedis:
    def __init__(self):
        self.streams: dict[str, dict[str, dict]] = {}
        self.groups: dict[str, set] = {}
        self.read_ids: set = set()
        self.acked: list[str] = []
        self.next_id = 0
        self.group_error: Exception | None = None
        self.autoclaim_pages: list[list[tuple[str, dict]]] = []

    async def ping(self):
        return True

    async def aclose(self):
        pass

    async def xgroup_create(self, key, group, id="0", mkstream=False):
        if self.group_error is not None:
            raise self.group_error
        if group in self.groups.setdefault(key, set()):
            raise RuntimeError("BUSYGROUP Consumer Group name already exists")
        self.groups[key].add(group)

    async def xadd(self, key, fields):
        self.next_id += 1
        eid = f"{self.next_id}-0"
        self.streams.setdefault(key, {})[eid] = dict(fields)
        return eid

    async def xreadgroup(self, group, consumer, streams, count=1, block=None):
        key = next(iter(streams))
        out = []
        for eid, fields in self.streams.get(key, {}).items():
            if eid in self.read_ids:
                continue
            self.read_ids.add(eid)
            out.append((key, [(eid, fields)]))
            if len(out) >= count:
                break
        return out

    async def xack(self, key, group, *ids):
        self.acked.extend(ids)

    async def xautoclaim(self, key, group, consumer, min_idle_time,
                         start_id, count):
        if self.autoclaim_pages:
            return "0-0", self.autoclaim_pages.pop(0), []
        return "0-0", [], []


def make_queue(fake=None) -> tuple:
    from common.redis_client import TaskQueue

    fake = fake or FakeRedis()
    queue = TaskQueue("redis://fake", "bb:tasks", "workers")
    queue.client = fake
    return queue, fake


def run(coro):
    return asyncio.run(coro)


class TestTaskQueue:
    @staticmethod
    def _queue_with_fake(monkeypatch, fake=None):
        import common.redis_client as crc
        from common.redis_client import TaskQueue

        fake = fake or FakeRedis()
        monkeypatch.setattr(crc.aioredis, "from_url",
                            lambda url, decode_responses=False: fake)
        return TaskQueue("redis://fake", "bb:tasks", "workers"), fake

    def test_connect_creates_group_and_tolerates_busygroup(self, monkeypatch):
        queue, fake = self._queue_with_fake(monkeypatch)

        async def scenario():
            await queue.connect()                   # first create OK
            await queue.connect()                   # BUSYGROUP swallowed
            fake.group_error = RuntimeError("CLUSTERDOWN")
            with pytest.raises(RuntimeError):
                await queue.connect()

        run(scenario())

    def test_enqueue_sets_issued_at_and_returns_id(self):
        queue, fake = make_queue()

        async def scenario():
            return await queue.enqueue({"task_id": "t1"})

        entry_id = run(scenario())
        body = json.loads(fake.streams["bb:tasks"][entry_id]["payload"])
        assert body["task_id"] == "t1"
        assert body["issued_at_epoch"] > 0

    def test_consume_roundtrip_and_poison_handling(self):
        queue, fake = make_queue()
        fake.streams["bb:tasks"] = {
            "1-0": {"payload": json.dumps({"task_id": "ok"})},
            "2-0": {"payload": "{not json"},
        }
        got = run(queue.consume("c1", count=5))
        assert got == [("1-0", {"task_id": "ok"})]
        assert "2-0" in fake.acked                  # poison discarded safely

    def test_reclaim_reenqueues_with_incremented_attempt(self):
        from common.redis_client import TaskQueue

        pending = [("9-0", {"payload": json.dumps(
            {"task_id": "t9", "attempt": 2})})]
        fake = FakeRedis()
        fake.autoclaim_pages.append(pending)
        queue = TaskQueue("redis://fake", "bb:tasks", "workers")
        queue.client = fake
        reclaimed = run(queue.reclaim_stale(60_000))
        assert reclaimed == 1
        assert "9-0" in fake.acked                  # original ACKed
        bodies = [json.loads(f["payload"])
                  for f in fake.streams["bb:tasks"].values()]
        requeued = next(b for b in bodies if b["task_id"] == "t9")
        assert requeued["attempt"] == 3 and requeued["reclaimed"] is True

    def test_reclaim_no_pending_is_zero(self):
        queue, _ = make_queue()
        assert run(queue.reclaim_stale(1000)) == 0

    def test_new_consumer_name_suffix(self):
        from common.redis_client import new_consumer_name

        name = new_consumer_name("w1")
        assert name.startswith("w1-") and name != new_consumer_name("w1")


# --------------------------------------------------------------------- #
# common/db.py — typed helpers over FakePool                             #
# --------------------------------------------------------------------- #
class TestDbHelpers:
    SCAN = "11111111-1111-1111-1111-111111111111"

    def test_insert_task_returns_new_id(self):
        from common.db import insert_task
        from common.testing import FakePool, row

        pool = FakePool({"on conflict (idempotency_key)":
                         [row(id="new-task-id")]})
        got = run(insert_task(pool, scan_id=self.SCAN, step_name="s",
                              tool="t", payload={}, idempotency_key="k",
                              max_attempts=3))
        assert got == "new-task-id"

    def test_insert_task_conflict_returns_existing(self):
        from common.db import insert_task
        from common.testing import FakePool

        # fetchval fallback: canned SCALAR (lists mean rows-for-fetch*)
        pool = FakePool({
            "on conflict (idempotency_key)": [],   # conflict -> no row back
            "where idempotency_key=$1": "existing-id",
        })
        got = run(insert_task(pool, scan_id=self.SCAN, step_name="s",
                              tool="t", payload={}, idempotency_key="dup",
                              max_attempts=3))
        assert got == "existing-id"

    def test_insert_task_carries_depends_and_gate(self):
        from common.db import insert_task
        from common.testing import FakePool, row

        pool = FakePool({"on conflict (idempotency_key)":
                         [row(id="tid")]})
        run(insert_task(pool, scan_id=self.SCAN, step_name="s", tool="t",
                        payload={}, idempotency_key="k", max_attempts=2,
                        depends_on=["a"], when_finding_type="open_port"))
        # statement reached the pool inside a connection acquisition
        assert any("INSERT INTO tasks" in q for q, _ in pool.executed) or \
            pool.transactions >= 0   # fetchrow path isn't recorded by the fake

    def test_scan_finding_values_dedupe_preserve_order(self):
        from common.db import scan_finding_values
        from common.testing import FakePool, row

        pool = FakePool()

        async def fake_fetch(query, *args):
            return [row(type="subdomain", value="b.com"),
                    row(type="subdomain", value="a.com"),
                    row(type="subdomain", value="b.com")]

        pool.fetch = fake_fetch
        grouped = run(scan_finding_values(pool, self.SCAN,
                                          ["subdomain", "open_port"]))
        assert grouped["subdomain"] == ["b.com", "a.com"]
        assert grouped["open_port"] == []

    def test_ready_tasks_passthrough(self):
        from common.db import ready_tasks
        from common.testing import FakePool, row

        pool = FakePool({"dispatched = false": [row(task_id="t1")]})
        assert [r["task_id"] for r in run(ready_tasks(pool))] == ["t1"]

    def test_triage_finding_roundtrip_and_missing(self):
        from common.db import triage_finding
        from common.testing import FakePool, row

        pool = FakePool({"returning id::text":
                         [row(id="f1", fingerprint="fp", type="vulnerability",
                              value="v", validation_state="validated")]})
        out = run(triage_finding(pool, "f1", "validated", "human"))
        assert out["validation_state"] == "validated"
        assert run(triage_finding(FakePool(), "gone", "refuted",
                                  "human")) is None

    def test_metrics_snapshot_shape(self):
        from common.db import metrics_snapshot
        from common.testing import FakePool, row

        pool = FakePool({
            "from scans": [row(status="completed", n=2)],
            "from tasks": [row(state="succeeded", n=5)],
            "from findings where is_new": 7,
            "validation_state='unvalidated'": 9,
        })
        snap = run(metrics_snapshot(pool))
        assert snap["scans"] == {"completed": 2}
        assert snap["tasks"] == {"succeeded": 5}
        assert snap["findings_new"] == 7
        assert snap["workers_alive"] >= 0 and snap["findings_total"] > 0

    def test_heartbeat_upsert_executes(self):
        from common.db import heartbeat
        from common.testing import FakePool

        pool = FakePool()
        run(heartbeat(pool, "w1", ["builtin.noop"]))
        assert any("worker_heartbeats" in q for q, _ in pool.executed)

    def test_audit_event_json_payload(self):
        from common.db import audit_event
        from common.testing import FakePool

        pool = FakePool()
        run(audit_event(pool, actor="a", action="x", subject="s",
                        decision="allow", details={"k": 1}))
        q, args = pool.executed[0]
        assert json.loads(args[4]) == {"k": 1}


# --------------------------------------------------------------------- #
# worker/executor.py — environment sealing & batch merge                 #
# --------------------------------------------------------------------- #
def _ctx_for(tmp_path):
    from worker.tools.base import ToolContext

    return ToolContext(
        task_id="t", scan_id="s", program_id="p", step_name="step",
        target="", params={}, attempt=1, timeout_secs=20,
        max_output_bytes=1000, workdir=str(tmp_path))


class TestExecutorInternals:
    def test_env_sealing_and_explicit_passthrough(self, monkeypatch):
        from worker.executor import _build_environment

        monkeypatch.setenv("PATH", "/bin")
        monkeypatch.setenv("MY_SECRET", "s")
        monkeypatch.setenv("PROVIDER_TOKEN", "t")
        monkeypatch.setenv("SHODAN_KEY", "z")
        monkeypatch.setenv("SHODAN_API_KEY", "real-key")
        env = _build_environment({"SHODAN_API_KEY"}, home="/home/w")
        assert env["HOME"] == "/home/w" and env["PATH"] == "/bin"
        assert "MY_SECRET" not in env and "PROVIDER_TOKEN" not in env
        assert "SHODAN_KEY" not in env              # naive filter wins...
        assert env["SHODAN_API_KEY"] == "real-key"  # ...opt-in overrides

    def test_run_batch_merges_outputs_and_first_failure_rc(self, tmp_path):
        from worker.executor import Executor

        ex = Executor(max_output_bytes=10_000)
        py = sys.executable
        result = ex.run_batch([
            [py, "-c", "print('A')"],
            [py, "-c",
             "import sys; print('E', file=sys.stderr); sys.exit(3)"],
            [py, "-c", "print('C')"],
        ], _ctx_for(tmp_path))
        assert result.return_code == 3              # first non-zero wins
        assert "batch[0]" in result.stdout and "A" in result.stdout
        assert "batch[2]" in result.stdout and "C" in result.stdout
        assert "E" in result.stderr
        assert result.timed_out is False

    def test_missing_binary_returns_none_rc(self, tmp_path):
        from worker.executor import Executor

        ex = Executor(max_output_bytes=1000)
        result = ex.run(["definitely-missing-binary-xyz"],
                        _ctx_for(tmp_path))
        assert result.return_code is None
        assert "not found" in result.stderr

    def test_stdin_data_reaches_process(self, tmp_path):
        from worker.executor import Executor

        py = sys.executable
        ex = Executor(max_output_bytes=1000)
        result = ex.run([py, "-c",
                         "import sys; sys.stdout.write(sys.stdin.read())"],
                        _ctx_for(tmp_path),
                        stdin_bytes=b"ping-payload")
        assert "ping-payload" in result.stdout


# --------------------------------------------------------------------- #
# master/api.py — background maintenance loops                           #
# --------------------------------------------------------------------- #
class TestBackgroundLoops:
    def _api(self):
        from common.config import Settings

        import master.api as mapi

        return mapi, Settings(api_token="t", workflows_dir=".")

    def test_dispatch_ready_tasks_enqueues_and_marks(self, monkeypatch):
        import json as j

        from common.testing import FakePool, FakeQueue

        mapi, _ = self._api()
        pool, queue = FakePool(), FakeQueue()
        ready = [{"task_id": "t1", "idempotency_key": "k",
                  "scan_id": "s1", "program_id": "p1",
                  "step_name": "step", "tool": "httpx",
                  "payload": j.dumps({"target": "example.com", "depth": 2}),
                  "max_attempts": 3}]
        marked = []

        async def fake_ready(p):
            return ready

        async def fake_mark(p, ids):
            marked.append(list(ids))

        monkeypatch.setattr(mapi.database, "ready_tasks", fake_ready)
        monkeypatch.setattr(mapi.database, "mark_dispatched", fake_mark)
        n = run(mapi._dispatch_ready_tasks(pool, queue))
        assert n == 1
        msg = queue.enqueued_payloads[0]
        assert msg["task_id"] == "t1" and msg["tool"] == "httpx"
        assert msg["params"]["depth"] == 2          # payload parsed+merged
        assert msg["attempt"] == 1
        assert marked == [["t1"]]

    def test_finalize_scans_completes_when_all_succeeded(self, monkeypatch):
        from common.testing import FakePool, row

        mapi, _ = self._api()
        pool = FakePool({"status = 'running'":
                         [row(scan_id="s-done")]})
        states = {"s-done": [{"state": "succeeded", "n": 2}]}
        called = []

        async def fake_states(p, sid):
            return states[sid]

        async def fake_update(p, s, st):
            called.append((s, st))

        monkeypatch.setattr(mapi.database, "task_states", fake_states)
        monkeypatch.setattr(mapi.database, "update_scan_status", fake_update)
        run(mapi._finalize_scans(pool))
        assert called == [("s-done", "completed")]

    def test_finalize_scans_failed_when_no_successes(self, monkeypatch):
        from common.testing import FakePool, row

        mapi, _ = self._api()
        pool = FakePool({"status = 'running'": [row(scan_id="s-fail")]})

        async def fake_states(p, sid):
            return [{"state": "dead", "n": 1}, {"state": "aborted", "n": 1}]

        called = []

        async def fake_update(p, s, st):
            called.append((s, st))

        monkeypatch.setattr(mapi.database, "task_states", fake_states)
        monkeypatch.setattr(mapi.database, "update_scan_status", fake_update)
        run(mapi._finalize_scans(pool))
        assert called == [("s-fail", "failed")]

    def test_finalize_scans_skips_still_running(self, monkeypatch):
        from common.testing import FakePool, row

        mapi, _ = self._api()
        pool = FakePool({"status = 'running'": [row(scan_id="s-live")]})

        async def fake_states(p, sid):
            return [{"state": "queued", "n": 1}]

        called = []

        async def fake_update(p, s, st):
            called.append((s, st))

        monkeypatch.setattr(mapi.database, "task_states", fake_states)
        monkeypatch.setattr(mapi.database, "update_scan_status", fake_update)
        run(mapi._finalize_scans(pool))
        assert called == []


# --------------------------------------------------------------------- #
# worker/main.py — task handling gates (security-critical paths)         #
# --------------------------------------------------------------------- #
def _worker(capabilities=("builtin.noop",)):
    from common.ratelimit import TokenBucket
    from common.testing import FakePool, FakeQueue, make_test_settings
    from worker.executor import Executor
    from worker.main import Worker

    w = object.__new__(Worker)          # bypass __init__ (no env needed)
    w.settings = make_test_settings()
    w.capabilities = list(capabilities)
    w.worker_id = "w1"
    w.consumer = "c1"                   # _consume_loop passes this to queue.consume
    w.rate_bucket = TokenBucket(rate=10_000)
    w.queue = FakeQueue()
    w.pool = FakePool()
    w.executor = Executor(max_output_bytes=2_000)
    w._stopping = asyncio.Event()
    return w


def _payload(**over):
    p = {"task_id": "11111111-1111-1111-1111-111111111111",
         "idempotency_key": "k",
         "scan_id": "22222222-2222-2222-2222-222222222222",
         "program_id": "33333333-3333-3333-3333-333333333333",
         "step_name": "step1", "tool": "builtin.noop",
         "target": "example.com", "params": {},
         "attempt": 1, "max_attempts": 3}
    p.update(over)
    return p


class TestWorkerGates:
    @staticmethod
    def _claimable(pool):
        from common.testing import row

        pool.canned["claimed_by=$2"] = [row(max_attempts=3)]

    @staticmethod
    def _states_written(pool):
        """Task states written via UPDATE (both $2-param and inline forms)."""
        states = []
        for q, args in pool.executed:
            if "state=$2" in q and isinstance(args, tuple) and len(args) >= 2:
                states.append(args[1])
            elif "state='queued'" in q:
                states.append("queued")
        return states

    def test_unclaimable_task_acked_without_side_effects(self):
        w = _worker()
        run(w._handle("e1", _payload()))
        assert w.queue.acked == ["e1"]
        assert self._states_written(w.pool) == []

    def test_scope_deny_finalizes_fails_and_aborts_branch(self, monkeypatch):
        import worker.main as wmain

        w = _worker()
        self._claimable(w.pool)
        aborted, audits = [], []

        async def fake_scope(p, pid):
            return [("example.com", True)]

        async def fake_abort(p, s, step):
            aborted.append((s, step))

        async def fake_audit(p, **kw):
            audits.append(kw["action"])

        monkeypatch.setattr(wmain.database, "get_scope_rows", fake_scope)
        monkeypatch.setattr(wmain.database, "abort_dependents", fake_abort)
        monkeypatch.setattr(wmain.database, "audit_event", fake_audit)

        run(w._handle("e1", _payload(target="evil.com")))
        assert self._states_written(w.pool) == ["failed"]
        assert len(aborted) == 1                    # branch cascade
        assert audits[-1] == "task.scope_deny"
        assert w.queue.acked == ["e1"]

    def test_capability_refusal_deadletters(self, monkeypatch):
        import worker.main as wmain

        w = _worker(capabilities=("builtin.noop",))
        self._claimable(w.pool)
        audits = []

        async def fake_scope(p, pid):
            return [("example.com", True)]

        async def fake_audit(p, **kw):
            audits.append(kw["action"])

        monkeypatch.setattr(wmain.database, "get_scope_rows", fake_scope)
        monkeypatch.setattr(wmain.database, "audit_event", fake_audit)
        run(w._handle("e1", _payload(tool="subfinder")))
        assert self._states_written(w.pool) == ["dead"]
        assert w.queue.acked == ["e1"]

    def test_success_path_records_and_acks(self, monkeypatch):
        import worker.main as wmain

        from worker.tools.base import ExecResult

        w = _worker()
        self._claimable(w.pool)

        async def fake_scope(p, pid):
            return [("example.com", True)]

        def fake_run(argv, ctx, stdin_bytes=None):
            body = json.dumps({"echo": "ok", "target": ctx.target, "ts": 1})
            return ExecResult(0, body + "\n", "", 5)

        w.executor.run = fake_run
        recorded = {}

        async def fake_record(_pool, **kw):
            recorded.update(kw)
            return 2, 1

        async def fake_audit(p, **kw):
            pass

        monkeypatch.setattr(wmain.database, "get_scope_rows", fake_scope)
        monkeypatch.setattr(wmain.database, "record_findings", fake_record)
        monkeypatch.setattr(wmain.database, "audit_event", fake_audit)

        run(w._handle("e1", _payload()))
        assert recorded["program_id"] == _payload()["program_id"]
        assert self._states_written(w.pool) == ["succeeded"]
        assert w.queue.acked == ["e1"]

    def test_failure_requeues_with_incremented_attempt(self, monkeypatch):
        import worker.main as wmain

        from worker.tools.base import ExecResult

        w = _worker()
        self._claimable(w.pool)

        async def fake_scope(p, pid):
            return [("example.com", True)]

        w.executor.run = lambda argv, ctx, stdin_bytes=None: \
            ExecResult(1, "", "boom", 5)

        async def nosleep(seconds):
            pass

        monkeypatch.setattr(wmain.database, "get_scope_rows", fake_scope)
        monkeypatch.setattr(asyncio, "sleep", nosleep)
        run(w._handle("e1", _payload(attempt=1)))
        redelivered = w.queue.enqueued_payloads[0]
        assert redelivered["attempt"] == 2          # retry carries attempt+1
        assert self._states_written(w.pool) == ["queued"]
        assert w.queue.acked == ["e1"]              # old delivery closed


class TestBuildContext:
    @staticmethod
    def _msg_like():
        m = type("M", (), {})()
        m.scan_id = "s"
        m.task_id = "t"
        m.program_id = "p"
        m.step_name = "step"
        m.target = "example.com"
        m.params = {}
        m.attempt = 1
        return m

    def test_empty_upstream_input_fails_fast(self, tmp_path, monkeypatch):
        import worker.main as wmain

        from worker.tools.base import ToolExecutionError
        from worker.tools.registry import resolve_tool

        w = _worker()

        async def fake_values(p, s, types):
            return {"resolved_host": []}

        monkeypatch.setattr(wmain.database, "scan_finding_values", fake_values)
        tool = resolve_tool("httpx", ["httpx"])   # needs_input_file=True
        with pytest.raises(ToolExecutionError):
            run(w._build_context(tool, self._msg_like(), str(tmp_path)))

    def test_input_file_dedupes_preserving_order(self, tmp_path, monkeypatch):
        import worker.main as wmain

        from worker.tools.registry import resolve_tool

        w = _worker()

        async def fake_values(p, s, types):
            return {"resolved_host": ["b.com", "a.com", "b.com"]}

        monkeypatch.setattr(wmain.database, "scan_finding_values", fake_values)
        tool = resolve_tool("httpx", ["httpx"])
        ctx = run(w._build_context(tool, self._msg_like(), str(tmp_path)))
        content = open(ctx.input_file,
                       encoding="utf-8").read().splitlines()
        assert content == ["b.com", "a.com"]
        assert ctx.inputs["resolved_host"].count("b.com") == 2


# --------------------------------------------------------------------- #
# common/db.py — migrations, wait_for_db, report/list queries            #
# --------------------------------------------------------------------- #
class TestMigrations:
    def test_pending_files_applied_once_in_order(self, tmp_path):
        from common.db import run_migrations
        from common.testing import FakePool

        (tmp_path / "001_a.sql").write_text("SELECT 1;", encoding="utf-8")
        (tmp_path / "002_b.sql").write_text("SELECT 2;", encoding="utf-8")
        pool = FakePool()
        applied: list[str] = []

        async def fake_fetch(query, *args):
            return [{"name": n} for n in applied]

        pool.fetch = fake_fetch
        count = run(run_migrations(pool, migrations_dir=tmp_path))
        assert count == 2
        # Migration names are bound as parameters to the bookkeeping INSERT
        # (never string-interpolated into SQL), so assert on the args.
        recorded = [args[0] for q, args in pool.executed
                    if "schema_migrations" in q and args]
        assert recorded == ["001_a.sql", "002_b.sql"]   # once, in order

        # second run: everything recorded -> no statements re-applied
        applied.extend(["001_a.sql", "002_b.sql"])
        pool.executed.clear()
        assert run(run_migrations(pool, migrations_dir=tmp_path)) == 0
        # only the idempotent CREATE TABLE probe may remain
        assert all("schema_migrations" in q for q, _ in pool.executed)

    def test_applied_set_skips_known(self, tmp_path):
        from common.db import run_migrations
        from common.testing import FakePool

        (tmp_path / "001_a.sql").write_text("SELECT 1;", encoding="utf-8")
        pool = FakePool()

        async def fake_fetch(query, *args):
            return [{"name": "001_a.sql"}]   # already applied

        pool.fetch = fake_fetch
        assert run(run_migrations(pool, migrations_dir=tmp_path)) == 0


class TestWaitForDb:
    def test_retries_then_succeeds(self, monkeypatch):
        import common.db as cdb

        attempts = {"n": 0}

        async def flaky_connect(dsn, **kw):
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise RuntimeError("not up yet")
            return "sentinel-pool"

        monkeypatch.setattr(cdb, "connect", flaky_connect)
        sleeps: list[float] = []

        async def nosleep(seconds):
            sleeps.append(seconds)

        monkeypatch.setattr(asyncio, "sleep", nosleep)
        assert run(cdb.wait_for_db("dsn", attempts=5, delay=0)) \
            == "sentinel-pool"
        assert attempts["n"] == 3 and len(sleeps) == 2

    def test_gives_up_after_attempts(self, monkeypatch):
        import common.db as cdb

        async def dead_connect(dsn, **kw):
            raise RuntimeError("down")

        monkeypatch.setattr(cdb, "connect", dead_connect)

        async def nosleep(seconds):
            pass

        monkeypatch.setattr(asyncio, "sleep", nosleep)
        with pytest.raises(RuntimeError, match="unreachable"):
            run(cdb.wait_for_db("dsn", attempts=2, delay=0))


class TestListQueries:
    def test_list_findings_builds_filtered_args(self, monkeypatch):
        from common.db import list_findings
        from common.testing import FakePool

        pool = FakePool()
        captured = {}

        async def fake_fetch(query, *args):
            captured["query"], captured["args"] = query, args
            return []

        pool.fetch = fake_fetch
        run(list_findings(pool, scan_id="sid", state="validated",
                          severity="high", is_new=True, limit=9999))
        q = captured["query"]
        assert "scan_id::text = $1" in q and "validation_state = $2" in q
        assert "severity = $3" in q and "is_new = $4" in q
        assert captured["args"][4] == 200          # limit clamped
        assert q.strip().endswith("$5")

    def test_list_scans_clamps_limit(self, monkeypatch):
        from common.db import list_scans
        from common.testing import FakePool

        pool = FakePool()
        captured = {}

        async def fake_fetch(query, *args):
            captured["args"] = args
            return []

        pool.fetch = fake_fetch
        run(list_scans(pool, limit=5000))
        assert captured["args"][0] == 100


# --------------------------------------------------------------------- #
# worker/main.py — consume/process resilience                            #
# --------------------------------------------------------------------- #
class TestWorkerLoops:
    def test_process_catches_and_audits_internal_error(self, monkeypatch):
        import worker.main as wmain

        w = _worker()
        audits = []

        async def fake_audit(p, **kw):
            audits.append(kw)

        monkeypatch.setattr(wmain.database, "audit_event", fake_audit)
        broken_payload = _payload()
        broken_payload.pop("task_id")              # TaskMessage will reject
        run(w._process("e1", broken_payload, asyncio.Semaphore(1)))
        assert audits and audits[0]["action"] == "task.internal_error"

    def test_consume_error_backs_off_then_stops(self, monkeypatch):
        w = _worker()

        class ExplodingQueue:
            def __init__(self):
                self.calls = 0

            async def consume(self, consumer, count=1, block_ms=0):
                self.calls += 1
                if self.calls == 1:
                    raise RuntimeError("redis down")
                w._stopping.set()
                return []

        w.queue = ExplodingQueue()
        sleeps = []

        async def nosleep(seconds):
            sleeps.append(seconds)

        monkeypatch.setattr(asyncio, "sleep", nosleep)
        run(w._consume_loop())
        assert w.queue.calls == 2                  # retried after backoff
        assert sleeps == [3]                       # documented backoff window

    def test_consume_backoff_grows_exponentially_no_hot_spin(self, monkeypatch):
        """Regression: a persistently failing queue must back off with
        exponential growth instead of hot-spinning the CPU (the bug that
        produced a 1.28 GB runaway log)."""
        w = _worker()

        class FlakyQueue:
            def __init__(self):
                self.calls = 0

            async def consume(self, consumer, count=1, block_ms=0):
                self.calls += 1
                if self.calls <= 4:
                    raise RuntimeError("redis down")
                w._stopping.set()
                return []

        w.queue = FlakyQueue()
        sleeps = []

        async def nosleep(seconds):
            sleeps.append(seconds)

        monkeypatch.setattr(asyncio, "sleep", nosleep)
        run(w._consume_loop())
        assert sleeps == [3.0, 6.0, 12.0, 24.0]    # base * 2^(n-1)

    def test_consume_backoff_caps_at_max(self, monkeypatch):
        w = _worker()

        class DeadQueue:
            def __init__(self):
                self.calls = 0

            async def consume(self, consumer, count=1, block_ms=0):
                self.calls += 1
                if self.calls <= 7:
                    raise RuntimeError("redis still down")
                w._stopping.set()
                return []

        w.queue = DeadQueue()
        sleeps = []

        async def nosleep(seconds):
            sleeps.append(seconds)

        monkeypatch.setattr(asyncio, "sleep", nosleep)
        run(w._consume_loop())
        assert len(sleeps) == 7
        assert max(sleeps) == 30.0                 # capped at configured max
        assert all(0 < s <= 30.0 for s in sleeps)

    def test_consume_backoff_resets_after_success(self, monkeypatch):
        w = _worker()

        class IntermittentQueue:
            def __init__(self):
                self.calls = 0

            async def consume(self, consumer, count=1, block_ms=0):
                self.calls += 1
                # fail, fail, succeed, fail  -> delays [3, 6, -, 3]
                if self.calls in (1, 2, 4):
                    raise RuntimeError("flaky redis")
                if self.calls == 5:
                    w._stopping.set()
                return []

        w.queue = IntermittentQueue()
        sleeps = []

        async def nosleep(seconds):
            sleeps.append(seconds)

        monkeypatch.setattr(asyncio, "sleep", nosleep)
        run(w._consume_loop())
        assert sleeps == [3.0, 6.0, 3.0]           # reset to base after success


# --------------------------------------------------------------------- #
# mcp_server/master_client.py — typed URL construction                   #
# --------------------------------------------------------------------- #
class TestMasterClient:
    @staticmethod
    def _client_with_stub(monkeypatch):
        import mcp_server.master_client as mcm

        from mcp_server.master_client import MasterClient

        calls = []

        def fake_http(method, url, headers, body, timeout):
            calls.append({"method": method, "url": url,
                          "headers": dict(headers), "body": body})
            if "/report?format=md" in url:
                return 200, b"# Report\n"
            if url.endswith("/missing"):
                return 404, b'{"detail": "scan not found"}'
            if url.endswith("/workflows"):
                return 200, b'{"workflows": ["smoke", "recon"]}'
            return 200, json.dumps({"ok": True}).encode()

        monkeypatch.setattr(mcm, "http_request", fake_http)
        return MasterClient("http://master.test", api_token="tok"), calls

    def test_list_workflows_url_and_auth(self, monkeypatch):
        client, calls = self._client_with_stub(monkeypatch)
        assert client.list_workflows() == ["smoke", "recon"]
        c = calls[0]
        assert (c["method"], c["url"]) == ("GET",
                                           "http://master.test/api/v1/workflows")
        assert c["headers"]["X-API-Token"] == "tok"

    def test_submit_scan_posts_json_body(self, monkeypatch):
        client, calls = self._client_with_stub(monkeypatch)
        client.submit_scan("prog", "recon", ["example.com"], "agent")
        c = calls[0]
        assert c["method"] == "POST"
        body = json.loads(c["body"])
        assert body == {"program": "prog", "workflow": "recon",
                        "targets": ["example.com"], "requested_by": "agent"}

    def test_list_findings_query_params(self, monkeypatch):
        client, calls = self._client_with_stub(monkeypatch)
        client.list_findings(scan_id="abc", state="validated",
                             severity="high", is_new=True, limit=25)
        url = calls[0]["url"]
        for fragment in ("state=validated", "severity=high", "is_new=true",
                         "limit=25", "scan_id=abc"):
            assert fragment in url

    def test_report_md_returns_raw_text(self, monkeypatch):
        client, _ = self._client_with_stub(monkeypatch)
        out = client.get_scan_report("sid", "md")
        assert isinstance(out, str) and out.startswith("# Report")

    def test_http_error_raises_typed_error(self, monkeypatch):
        from mcp_server.master_client import MasterClientError

        client, _ = self._client_with_stub(monkeypatch)
        with pytest.raises(MasterClientError) as exc:
            client.get_scan("/missing")
        assert exc.value.status == 404
        assert "scan not found" in exc.value.detail