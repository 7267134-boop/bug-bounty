-- ============================================================================
-- Migration 004: Human-in-the-loop triage + algorithmic routing gates
-- ============================================================================

-- Pillar B: who validated/refuted a finding, and when (audit-friendly).
ALTER TABLE findings ADD COLUMN IF NOT EXISTS validated_by TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS validated_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_findings_triage
    ON findings(validation_state, severity);

-- Pillar A: declarative dispatch gating - a step runs only after the scan
-- has produced at least one finding of the given type (event-driven routing).
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS when_finding_type TEXT;
