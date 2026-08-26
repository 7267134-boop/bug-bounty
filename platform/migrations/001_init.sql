-- ============================================================================
-- Migration 001: initial schema - programs, scope, scans, tasks, audit.
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Authorized bug bounty programs (one row per program/authorization record).
CREATE TABLE IF NOT EXISTS programs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name          TEXT NOT NULL UNIQUE,
    policy_url    TEXT,
    -- platform-wide politeness ceiling for this program
    max_rate_rps  INT  NOT NULL DEFAULT 10 CHECK (max_rate_rps BETWEEN 1 AND 1000),
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Scope entries: allow AND deny patterns per program.
CREATE TABLE IF NOT EXISTS scope_entries (
    id          BIGSERIAL PRIMARY KEY,
    program_id  UUID NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    pattern     TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('domain', 'wildcard', 'cidr')),
    is_allowed  BOOLEAN NOT NULL,
    note        TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (program_id, pattern)
);
CREATE INDEX IF NOT EXISTS idx_scope_program ON scope_entries(program_id);

-- A scan = one workflow execution against one program.
CREATE TABLE IF NOT EXISTS scans (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    program_id    UUID NOT NULL REFERENCES programs(id),
    workflow      TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending','running','completed','failed','cancelled')),
    requested_by  TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scan_targets (
    id         BIGSERIAL PRIMARY KEY,
    scan_id    UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    target     TEXT NOT NULL,
    decision   TEXT NOT NULL DEFAULT 'allow' CHECK (decision IN ('allow','deny')),
    reason     TEXT
);

-- Unit of work. idempotency_key makes planning replay-safe after crashes.
CREATE TABLE IF NOT EXISTS tasks (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id          UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    step_name        TEXT NOT NULL,
    tool             TEXT NOT NULL,
    payload          JSONB NOT NULL,
    state            TEXT NOT NULL DEFAULT 'queued'
                     CHECK (state IN ('queued','running','succeeded','failed','dead')),
    idempotency_key  TEXT NOT NULL UNIQUE,
    attempts         INT NOT NULL DEFAULT 0,
    max_attempts     INT NOT NULL DEFAULT 3,
    claimed_by       TEXT,
    claimed_at       TIMESTAMPTZ,
    finished_at      TIMESTAMPTZ,
    result           JSONB,
    error            TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_tasks_scan_state ON tasks(scan_id, state);
CREATE INDEX IF NOT EXISTS idx_tasks_state ON tasks(state) WHERE state IN ('queued','running');

-- Append-only audit trail: every authorization decision and lifecycle event.
CREATE TABLE IF NOT EXISTS audit_log (
    id        BIGSERIAL PRIMARY KEY,
    ts        TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    subject   TEXT,
    decision  TEXT NOT NULL CHECK (decision IN ('allow','deny','info','error')),
    details   JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);

-- Worker liveness.
CREATE TABLE IF NOT EXISTS worker_heartbeats (
    worker_id     TEXT PRIMARY KEY,
    capabilities  TEXT[] NOT NULL DEFAULT '{}',
    last_seen     TIMESTAMPTZ NOT NULL DEFAULT now()
);
