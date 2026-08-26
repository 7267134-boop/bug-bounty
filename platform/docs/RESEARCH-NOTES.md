# Research Notes — Ecosystem Analysis → Design Decisions (v0.2)

Condensed synthesis of the 29-project ecosystem study (2026-08). Full
per-project analysis lives in the project conversation/PR description; this
document records what we adopted and what we deliberately rejected.

## Adopted patterns (mapped to implementation)

| # | Source inspiration | Pattern | Our implementation |
|---|---|---|---|
| 1 | BBOT / OWASP Amass | Event-driven entity model; every discovered item is a typed event | `findings` table w/ typed entities (`type`,`value`); worker persists parsed findings per task |
| 2 | reNgine / Bug-Bounty-recon / Sublert-style monitors | State diffing: alert/report only on NEW assets between runs | `entity_fingerprint()` + `is_new` flag + `v_new_findings` view |
| 3 | DefectDojo | Deduplication as a first-class DB concern; findings lifecycle states | `UNIQUE(program, fingerprint, scan)` + `validation_state` (`unvalidated→validated/refuted`) |
| 4 | Zero-FP 4-agent model (evidence-gated progression) | Detection ≠ confirmation; only validated findings reach reporting | `validation_state` + `confidence` columns now; validation agent = later stage |
| 5 | Osmedeus | YAML workflows w/ dependencies & conditional dispatch; fanout modes | `depends_on` in schema (cycle-checked), `dispatched` flag + master dispatcher loop, `fanout: per_target/once` |
| 6 | DeepBounty / Osmedeus server-worker | Isolated horizontally-scalable workers; server never executes | Already Stage 1 core — preserved |
| 7 | bb-engine (Rust) | FP reduction via baseline comparison/similarity thresholds; evidence preservation | `confidence NUMERIC`, full finding `metadata JSONB` preserved for evidence replay |
| 8 | reconftw / Axiom(Ax) | Politeness + distributed throughput | `TokenBucket` rate limiter before every tool launch (`WORKER_RATE_RPS`) |
| 9 | notify (projectdiscovery) | Pluggable notification providers behind one hub | `common/notifications.py` webhook dispatcher, env-gated, failure-isolated |
| 10 | arkadiyt/bug-bounty-targets | Program scope data as structured input | `scripts/import_scope.py` validated CSV/JSON → SQL importer |
| 11 | reNgine dashboards / Reconmap ops views | Operational metrics exposure | `/metrics` Prometheus-style endpoint |
| 12 | PentestGPT / hackingBuddyGPT | LLM agents must be gated by deterministic tool contracts | Confirmed Stage-5 MCP design: typed wrappers only, no free-form shell |

## Rejected / deferred (with reasons)

- **Neo4j graph store (BBOT/Amass)**: powerful but operationally heavy for
  Stage 2; our normalized `findings` table captures the same relations until
  graph queries become a real need.
- **MongoDB (ARL)**: Postgres JSONB already covers semi-structured payloads
  without a second database to secure/back up.
- **Cloud fleet elasticity (Axiom/Ax)**: excellent pattern, but adds provider
  credentials + attack surface; revisit post-Stage-4 when scan volume justifies it.
- **Auto-enabling aggressive tasks by default (DeepBounty's
  ENABLE_AGGRESSIVE_TASKS)**: we keep capability allowlists fail-closed instead.

## Repos analyzed

Provided (9): reNgine, BBOT, Osmedeus, DeepBounty (dd060606), AutoAR,
ReconFTW, recon-pipeline (aenoshrajora), Bug-Bounty-recon (r46w), bb-engine
(ManU4kym).

Additional (20): OWASP Amass, Axiom (pry0cc), OneForAll, sn0int,
ShuiZe_0x727, DefectDojo, Faraday, ArcherySec, Reconmap, GVMD/OpenVAS,
Vuls, OWASP Nettacker, PentestGPT, hackingBuddyGPT, projectdiscovery/notify,
TIDoS-Framework, ARL (repo removed from GitHub; analyzed from archived
docs), FinalRecon, BugBountyScanner, arkadiyt/bug-bounty-targets.

Note: several small repos fetched had low community traction (≤5 stars);
their *ideas* were considered but weighted accordingly.
