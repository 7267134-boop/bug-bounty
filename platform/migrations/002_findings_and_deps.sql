-- ============================================================================
-- Migration 002: research-driven upgrades
--   * findings store w/ cross-scan deduplication (state diffing)
--   * evidence-gated validation states (zero-FP pipeline groundwork)
--   * dependency-aware task scheduling
-- ============================================================================

-- Workflow dependencies (Osmedeus-style conditional pipelines).
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS depends_on TEXT[] NOT NULL DEFAULT '{}';
-- Dispatch tracking: queued-but-not-yet-on-the-stream (waiting on deps).
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS dispatched BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX IF NOT EXISTS idx_tasks_pending_dispatch
    ON tasks(dispatched) WHERE dispatched = FALSE;

-- Normalized finding entities. One row per (program, fingerprint, scan);
-- fingerprint = sha256(program|type|value) enables cross-scan diffing and
-- reNgine/Sublert-style "only show me what's NEW" behaviour.
CREATE TABLE IF NOT EXISTS findings (
    id               BIGSERIAL PRIMARY KEY,
    program_id       UUID NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    scan_id          UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    task_id          UUID REFERENCES tasks(id) ON DELETE SET NULL,
    target           TEXT NOT NULL DEFAULT '',
    type             TEXT NOT NULL,           -- subdomain | live_host | open_port | vulnerability | ...
    value            TEXT NOT NULL,           -- canonical entity value
    severity         TEXT CHECK (severity IN ('critical','high','medium','low','info')),
    fingerprint      TEXT NOT NULL,
    -- TRUE when this fingerprint was never seen before for the program.
    is_new           BOOLEAN NOT NULL DEFAULT TRUE,
    -- Evidence-gated progression groundwork (zero-FP model):
    -- unvalidated -> validated | refuted ; reports only consume 'validated'.
    validation_state TEXT NOT NULL DEFAULT 'unvalidated'
                     CHECK (validation_state IN ('unvalidated','validated','refuted')),
    confidence       NUMERIC(3,2),
    metadata         JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (program_id, fingerprint, scan_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_program_fp ON findings(program_id, fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_validation ON findings(validation_state)
    WHERE validation_state = 'unvalidated';

-- Convenience view: deltas vs everything seen before this scan.
CREATE OR REPLACE VIEW v_new_findings AS
SELECT p.name AS program, sc.workflow, f.*
FROM findings f
JOIN scans sc ON sc.id = f.scan_id
JOIN programs p ON p.id = f.program_id
WHERE f.is_new;
