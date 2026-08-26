"""Executor failure modes, output caps, env passthrough, POSIX guards."""

import asyncio
import sys

from common.testing import make_test_settings
from worker.executor import Executor

from _helpers import _ctx  # noqa: F401  (shared builder)


def test_binary_not_found_is_clean_failure(tmp_path):
    result = Executor().run(
        ["definitely-not-a-binary-xyz"], _ctx(tmp_path))
    assert not result.ok
    assert result.return_code is None
    assert "not found" in result.stderr.lower()


def test_timeout_kills_process(tmp_path):
    code = "import time; time.sleep(30)"
    ex = Executor(max_output_bytes=1000)
    result = ex.run(
        [sys.executable, "-c", code], _ctx_alt(tmp_path, timeout_secs=1))
    assert result.timed_out and not result.ok
    assert "timeout" in result.stderr.lower()


def test_output_cap_enforced(tmp_path):
    # print far more than the cap; captured stdout must be truncated
    ex = Executor(max_output_bytes=2000)
    result = ex.run(
        [sys.executable, "-c", "print('x' * 50000)"],
        _ctx_alt(tmp_path))
    assert result.ok
    assert len(result.stdout) <= 2000


def test_env_passthrough_only_for_allowlisted_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "secret-shodan")
    monkeypatch.setenv("EVIL_SECRET_KEY", "should-not-pass")
    monkeypatch.setenv("SECURITYTRAILS_API_KEY", "")   # empty => not forwarded
    ex = Executor(extra_env_keys=["SHODAN_API_KEY", "SECURITYTRAILS_API_KEY"])
    seen = {}

    async def run():
        return ex.run(
            [sys.executable, "-c",
             "import json,os;print(json.dumps({k:v for k,v in os.environ.items() "
             "if 'KEY' in k}))"],
            _ctx_alt(tmp_path))

    result = asyncio.run(run())
    import json
    env = json.loads(result.stdout.strip())
    assert env.get("SHODAN_API_KEY") == "secret-shodan"
    assert "EVIL_SECRET_KEY" not in env
    assert "SECURITYTRAILS_API_KEY" not in env      # empty values skipped


def test_exit_code_propagates(tmp_path):
    result = Executor().run(
        [sys.executable, "-c", "import sys; sys.exit(3)"], _ctx_alt(tmp_path))
    assert result.return_code == 3 and not result.ok


def _ctx_alt(tmp_path, **kw):
    """Context with configurable fields (avoids helper signature churn)."""
    base = dict(task_id="t", scan_id="s", program_id="p", step_name="st",
                target="example.com", params={}, attempt=1,
                timeout_secs=kw.pop("timeout_secs", 10),
                max_output_bytes=100_000, workdir=str(tmp_path))
    base.update(kw)
    from worker.tools.base import ToolContext
    return ToolContext(**base)


def test_settings_defaults_safe():
    s = make_test_settings()
    assert s.task_timeout_secs == 5 and s.worker_rate_rps >= 100
