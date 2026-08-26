"""Shared builders for tool-wrapper tests (plain module, not a test file)."""

from worker.tools.base import ExecResult, ToolContext


def make_ctx(tmp_path, target="example.com", params=None, inputs=None,
             input_file=None) -> ToolContext:
    return ToolContext(
        task_id="t1", scan_id="s1", program_id="p1", step_name="step",
        target=target, params=params or {}, attempt=1, timeout_secs=30,
        max_output_bytes=100_000, workdir=str(tmp_path),
        inputs=inputs or {}, input_file=input_file,
    )


def make_result(stdout: str) -> ExecResult:
    return ExecResult(0, stdout, "", 10)


# Short aliases kept for terse test usage.
_ctx = make_ctx
_res = make_result
