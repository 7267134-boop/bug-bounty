"""Builtin tool drivers.

These are standalone Python programs executed by wrappers via
``[sys.executable, <driver>, ...]`` — still argv-list only (no shell),
still sandboxed by the executor, but kept as real modules so the protocol
logic stays testable without spawning processes.
"""