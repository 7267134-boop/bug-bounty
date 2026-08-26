# Bug Bounty Automation Platform

Distributed, authorized-bounty-only vulnerability discovery automation.

> ⚠️ **Legal**: run only against targets you are explicitly authorized to
> test. Every target is checked against program scope twice (master +
> worker); anything not explicitly allowed is blocked by default.

## Layout

| Path | What |
|---|---|
| [`platform/`](platform/) | The live distributed system (master API, workers, MCP gateway, dashboard) |
| [`legacy/stage0/`](legacy/README.md) | Superseded single-host orchestrator — history only |

## Quick start

```bash
cd platform
cp .env.example .env      # fill in secrets first!
docker compose up -d --build
# dashboard: http://localhost:8080/  (paste your MASTER_API_TOKEN)
```

Full runbook: [`platform/README.md`](platform/README.md) ·
architecture: [`platform/docs/ARCHITECTURE.md`](platform/docs/ARCHITECTURE.md) ·
tests: `cd platform && python -m pytest tests -q` (369 green)

## Quality gates

* Scope enforcement: default-deny + deny-wins, evaluated on master AND worker
* Sandboxed execution: argv-only, rlimits, timeouts, capability allowlists
* Human triage gate: only validated findings reach reports/AI
