-- ============================================================================
-- Seed: one demo program + scope. FOR LOCAL VALIDATION ONLY.
-- Usage:
--   docker compose exec -T postgres psql -U $POSTGRES_USER -d $POSTGRES_DB \
--       < scripts/seed.sql
--
-- Replace example.com with your ACTUAL authorized program scope.
-- ============================================================================

INSERT INTO programs (name, policy_url, max_rate_rps)
VALUES ('demo', 'https://example.com/security.txt', 10)
ON CONFLICT (name) DO UPDATE SET policy_url = EXCLUDED.policy_url;

DELETE FROM scope_entries
WHERE program_id = (SELECT id FROM programs WHERE name = 'demo');

-- In scope:
INSERT INTO scope_entries (program_id, pattern, kind, is_allowed, note)
SELECT id, 'example.com', 'domain', TRUE, 'apex + all subdomains'
FROM programs WHERE name = 'demo';

INSERT INTO scope_entries (program_id, pattern, kind, is_allowed, note)
SELECT id, '*.api.example.com', 'wildcard', TRUE, 'api wildcard demo'
FROM programs WHERE name = 'demo';

-- Explicitly out of scope (deny wins over allow):
INSERT INTO scope_entries (program_id, pattern, kind, is_allowed, note)
SELECT id, 'admin.example.com', 'domain', FALSE, 'admin panel excluded'
FROM programs WHERE name = 'demo';

INSERT INTO scope_entries (program_id, pattern, kind, is_allowed, note)
SELECT id, '10.0.0.0/8', 'cidr', FALSE, 'internal ranges never in scope'
FROM programs WHERE name = 'demo';
