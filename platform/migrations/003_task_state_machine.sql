-- ============================================================================
-- Migration 003: Stage-1 bugfix hardening
--   * explicit 'aborted' state for dependency-cascade teardown
--   * documents queue-state mapping (no schema churn for renames)
--
-- State machine (authoritative mapping):
--   pending  == state='queued'     AND dispatched=FALSE
--   enqueued == state='queued'     AND dispatched=TRUE
--   running / succeeded / failed / dead  == as named
--   aborted  == downstream of a failed/dead/aborted step (never dispatched)
-- ============================================================================

ALTER TABLE tasks DROP CONSTRAINT IF EXISTS tasks_state_check;
ALTER TABLE tasks ADD CONSTRAINT tasks_state_check
    CHECK (state IN ('queued','running','succeeded','failed','aborted','dead'));

-- Crash-window note: dispatch order is DB-insert -> XADD -> dispatched=TRUE.
-- A crash between XADD and the flag causes one redundant redelivery from the
-- 30s dispatcher loop; the worker's atomic claim
-- (UPDATE ... WHERE state IN ('queued','running')) makes duplicate deliveries
-- no-ops, and the SHA-256 idempotency key keeps replays side-effect free.
