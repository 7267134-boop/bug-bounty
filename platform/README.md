# Bug Bounty Automation Platform

Distributed, authorized-bounty-only vulnerability discovery automation.
Current release: **v0.3 — Stages 1–2 complete, Stage 4 PoC (dalfox/gowitness),
triage + routing gates live.**

## Architecture

Consolidated reference (components, ownership, state machines, trust
boundaries, cost model): [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

> ⚠️ The repo root also contains `legacy/stage0/` — the superseded
> single-host orchestrator, kept for history only. Do not extend it.

Production-grade, Linux-first, **distributed** vulnerability-discovery
automation for **explicitly authorized bug bounty programs only**.

> ⚠️ **Legal**: run this platform only against targets you are explicitly
> authorized to test. Every target is checked against the program's stored
> scope twice (master + worker); anything not explicitly allowed is blocked
> by default. Unauthorized use is illegal.

## Architecture (Stage 1)

```
                    ┌──────────────────────────────┐
   operator ──HTTPS──▶  Master Node (FastAPI)        │
                    │  - auth (X-API-Token)         │
                    │  - SCOPE GATE #1 (deny-wins)  │
                    │  - YAML workflow planner      │
                    │  - idempotent task planning   │
                    │  - stale-delivery reclaimer   │
                    │  - scan finalizer             │
                    └───────┬───────────┬──────────┘
                            │           │
                     Redis Streams   PostgreSQL
                     (task queue,     (durable state:
                      consumer groups) scans/tasks/audit)
                            │           │
                    ┌───────▼───────────▼──────────┐
                    │  Worker Node(s), Kali-based  │
                    │  - NO inbound ports          │
                    │  - SCOPE GATE #2 (defense    │
                    │    in depth)                 │
                    │  - capability allowlist      │
                    │  - sandboxed exec: argv-only,│
                    │    rlimits, timeouts, caps   │
                    │    dropped, read-only rootfs │
                    └──────────────────────────────┘
```

* **Master/Worker isolation** (DeepBounty-style): the planner never executes;
  the executor never accepts network connections.
* **YAML workflows** (Osmedeus-style): validated declarative steps in `workflows/`.
* **Queue/state/dedup** (reNgine-style): durable Postgres state + Redis Streams
  consumer groups; idempotency keys make replays safe.
* **Event routing** (BUG-Framework-style): typed task payloads + `when`
  gates — the decision engine is LIVE (see Stage 3 below).
* **MCP concepts** (BearStrike-style): tool access is mediated exclusively by
  typed wrappers with allowlists — Stage 5 adds the MCP server on the same gate
  model. No free-form shell anywhere.

## Security model

| Control | Implementation |
|---|---|
| Authorization | Program + scope rows in Postgres; API token (`X-API-Token`, constant-time compare) |
| Scope enforcement | `common/scope.py`: default-deny, deny-wins, wildcards/CIDRs, IDNA homograph defense, hard-blocked loopback/link-local/metadata endpoints; evaluated on master AND again on worker |
| Injection defense | Strict target charset regex; argv-list subprocess only (`shell=False`); workflow schema whitelist of keys/tools |
| Least privilege | Worker container: non-root UID 10001, `cap_drop ALL`, `no-new-privileges`, read-only rootfs, tmpfs scratch, pids/mem/cpu limits; child processes get POSIX rlimits |
| Rate limiting | Per-program `max_rate_rps` column enforced by tool wrappers (used from Stage 2) |
| Audit | Append-only `audit_log` table: every submit/deny/complete/dead-letter event |
| Retries | Bounded attempts with exponential backoff → dead-letter state |
| Idempotency | SHA-256 keys over (scan, step, tool, target, params); unique constraint suppresses duplicate planning after crashes |
| Crash recovery | Consumer groups + XAUTOCLAIM stale deliveries; task state machine in PG |

## Repository layout

```
platform/
├── docker-compose.yml         # hardened stack
├── .env.example               # secrets template (copy to .env)
├── common/                    # shared library (config, scope, events,
│                              #   db, redis_client, ids, logging_setup)
├── master/
│   ├── api.py                 # FastAPI: auth, scope gate, submission
│   ├── orchestrator.py        # YAML workflow loader/planner
│   ├── main.py                # uvicorn entrypoint
│   └── Dockerfile             # python:3.12-slim, non-root
├── worker/
│   ├── main.py                # consume loop + both security gates
│   ├── executor.py            # sandboxed subprocess runner
│   ├── tools/base.py          # typed ToolWrapper contract
│   ├── tools/registry.py      # registration + capability gate (+ builtin.noop)
│   └── Dockerfile             # Kali-based, non-root, no ports
├── migrations/001_init.sql    # programs/scope/scans/tasks/audit schema
├── workflows/smoke.yaml       # Stage 1 validation workflow
├── scripts/
│   ├── seed.sql               # demo program + scope (replace with real!)
│   └── validate_stage1.py     # end-to-end acceptance checks
└── tests/                     # runs locally without Docker
    ├── conftest.py
    ├── test_scope.py          # scope-enforcement unit tests
    └── test_workflows.py      # loader/planner/registry gate tests
```

## Setup & run (Linux host with Docker)

```bash
cd platform/
cp .env.example .env                 # replace every CHANGE_ME (openssl rand -hex 24)
docker compose build && docker compose up -d
docker compose ps                    # wait for healthy

# seed a program + scope (EDIT scripts/seed.sql to your REAL program first!)
docker compose exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
    < scripts/seed.sql

# or import scope from a validated CSV/JSON file:
python3 scripts/import_scope.py --program myprogram myscope.csv \
    | docker compose exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"

# end-to-end validation:
MASTER_URL=http://localhost:${MASTER_PORT:-8080} \
MASTER_API_TOKEN=$(grep '^MASTER_API_TOKEN=' .env | cut -d= -f2-) \
python3 scripts/validate_stage1.py

# operational metrics:
curl -s -H "X-API-Token: $MASTER_API_TOKEN" http://localhost:${MASTER_PORT:-8080}/metrics
```

## Extending (Stage 2 preview — do NOT implement yet)

1. Add a wrapper in `worker/tools/` (`@register`, implement `build_argv` + `parse`).
2. Add the tool name to the master's stage allowlist (`master/orchestrator.py`).
3. Add it to `WORKER_CAPABILITIES` in `.env`.
4. Reference it from a workflow step.

Fail-closed by construction: unregistered or non-allowlisted tools are refused.

## Roadmap

1. ✅ **Stage 1 — base architecture / orchestration / workers**
2. Recon: subfinder, assetfinder, httpx, katana, Shodan/SecurityTrails modes, dedup + state diffing
3. Event-driven routing: 403/CMS/login/Nmap decision engine
4. Focused scanning: nuclei severity filters, ffuf/dirsearch, Arjun, safe SSRF validation
5. MCP server behind strict guardrails (typed tools only, no free-form shell)
6. Unified reporting: JSON/Markdown, CVSS, PoC cURL reproduction, executive summary

## v0.2 upgrades (ecosystem-research driven)

Full analysis in [`docs/RESEARCH-NOTES.md`](docs/RESEARCH-NOTES.md):

* **Findings store + cross-scan state diffing** — typed entities with stable
  fingerprints; `is_new` flag + `v_new_findings` view ("only what changed").
* **Evidence-gated validation groundwork** — `validation_state`
  (`unvalidated/validated/refuted`) + `confidence` on every finding.
* **Dependency-aware workflows** — `depends_on` (acyclic-validated);
  dependent tasks dispatched only after upstream success.
* **Rate limiting** — token-bucket politeness ceiling per worker
  (`WORKER_RATE_RPS`) before every tool launch.
* **Notification hub** — env-gated webhook on scan finalization.
* **Scope importer** — validated CSV/JSON → SQL (`scripts/import_scope.py`).
* **Operational metrics** — authenticated `/metrics` Prometheus-style endpoint.

## Stage 2 toolchain

Ten production tools are now wrapped and pipeline-integrated (see
[`docs/TOOLCHAIN.md`](docs/TOOLCHAIN.md) for keep/exclude decisions):
`subfinder`, `assetfinder`, `amass`, `dnsx`, `httpx`, `naabu`,
`waybackurls`, `katana`, `nuclei`, `uncover`.

* Tools declare `consumes`/`produces` finding types; data flows through the
  findings store (no ad-hoc files between steps).
* `workflows/recon.yaml` chains them: passive enum → DNS → HTTP probe →
  ports → archive/crawl URLs → severity-filtered nuclei scan, with each step
  dispatched only after its dependencies succeed.
* Provider API keys reach tools only via explicit `WORKER_ENV_PASSTHROUGH`.
* Run it: submit a scan with `"workflow": "recon"` (file `workflows/recon.yaml`).

## Stage 3 — decision engine (LIVE)

Signals → routes, all declarative:

| Signal (finding type) | Emitted by | Routes to |
|---|---|---|
| `http_403` | httpx | `routing.bypass403` (R4) |
| `wordpress` | httpx | `wpscan` (R5) |
| `api_surface` | httpx | `corsy` (R6) |
| `url_param` | katana/waybackurls | `dalfox` (R3) |
| `open_port` | naabu | `nmap -sV -sC` targeted (R2) |
| – | – | massdns drops dead domains before anything (R1) |

Run it: submit with `"workflow": "deep-recon"`. Gated steps dispatch only
when their signal exists; failed upstream aborts its branch automatically.

## Stage 4 — focused scanning (LIVE)

Cost-first chain in [`workflows/focused.yaml`](workflows/focused.yaml):

| Step | Tool | Consumes → Produces | Gate |
|---|---|---|---|
| content_discovery | ffuf | live_host → discovered_url | live_host present |
| param_mining | arjun | live_host/api_surface → url_param | api_surface present |
| sqli_validation | sqlmap | url_param → vulnerability | url_param present |
| js_secrets | trufflehog | js_url → secret (redacted) | js_url present |
| oob_ssrf_probe | interactsh | url_param → vulnerability | url_param present |

`interactsh` is a builtin collaborator client (`drivers/interactsh.py`,
RSA-OAEP + AES, zero extra binaries): it injects a unique callback host into
every crawled parameter URL and correlates inbound interactions back to the
exact parameter that triggered them — blind SSRF becomes provable evidence.
Enable via `WORKER_CAPABILITIES=...,ffuf,arjun,sqlmap,trufflehog,interactsh`.

## Stage 5 — MCP gateway for AI agents (LIVE)

`mcp_server/` exposes the platform to AI agents over the **Model Context
Protocol** (JSON-RPC 2.0 / stdio) — with zero free-form shell by design:

* **Typed tools only**: `list_workflows`, `submit_scan`, `get_scan_status`,
  `list_findings`, `recent_scans`, `platform_metrics`. Every argument is
  schema-validated locally AND again by the master (defense in depth).
* **No triage tool — ever**: validate/refute stays a human decision
  (Pillar B); the gateway structurally refuses such calls.
* **No direct DB/Redis access**: the gateway talks only to the Master REST
  API (`MASTER_URL` + `MASTER_API_TOKEN`); the master remains single-writer.
* Resources: `platform://workflows`,
  `platform://findings/actionable` (pinned server-side to
  `validated`+`is_new=true`), `platform://scans/recent`.

Run an agent session:

```bash
export MASTER_API_TOKEN=...            # from .env
docker compose run --rm mcp           # or: python3 -m mcp_server.server
```

Protocol smoke test (any MCP client or plain JSON-RPC over stdin):

```json
{"jsonrpc":"2.0","id":1,"method":"initialize",
 "params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"x","version":"1"}}}
```

## Stage 6 — reporting engine (LIVE)

`GET /api/v1/scans/{scan_id}/report?format=json|md` (auth required) renders
the final deliverable. Pillar B is enforced **in the SQL**: only
human-`validated` AND `is_new` findings can ever reach a report — the
renderer cannot leak unvalidated noise even by accident.

Report contents:
* **Executive summary** — severity histogram + posture statement
  (URGENT when criticals exist).
* **Per-finding sections** ordered critical-first, each with CVSS
  score/vector when a tool computed one.
* **PoC cURL** — generated per finding type (CORS gets an `Origin:` probe
  header; secrets get NO request-PoC, only a rotate-the-credential note).
  Every URL passes a strict allowlist first; anything containing shell
  metacharacters (`'` `` ` `` `;` `$`) ships **without** a PoC instead of
  a dangerous one.

The same report is available to AI agents through MCP:
`get_scan_report {scan_id, format}`.

Programmatic use:

```python
from master.reporting import build_report, to_markdown
material = await database.report_material(pool, scan_id)
markdown = to_markdown(build_report(material))
```

## Testing & quality

See [`docs/TESTING.md`](docs/TESTING.md) (coverage plan, fakes) and
[`docs/PERFORMANCE.md`](docs/PERFORMANCE.md) (efficiency decisions incl.
the Python-vs-Go strategy). Control UI: point a browser at `/` and paste
the API token — read-only live status, zero JS dependencies.
