# Ecosystem Comparison — 50 Systems vs. This Platform (v0.4)

Method: 17 projects were re-verified live from their GitHub/docs this
session; the remaining entries continue the 29-project study recorded in
`RESEARCH-NOTES.md` plus well-established tools analyzed from long-form
documentation. ✱ = live-verified 2026-08.

Legend for "Take": A = pattern we adopted/applied now · P = partial/pending ·
R = rejected deliberately (reason in notes).

## 1. Orchestration platforms

| # | System | ✱ | Architecture | Pipeline | UI/Dashboard | Take |
|---|---|---|---|---|---|---|
| 1 | reNgine | ✱ | Django monolith + Celery | engines(YAML)→tasks→subscans | mature widgets, scheduling UI, BountyHub | A: passive preset, severity widget, ops dashboard ideas |
| 2 | BBOT | ✱ | async event bus, module graph | recursive events, presets | ASCII/web graphs, VivaGraphJS viz | P: event-graph viz later; presets validated |
| 3 | Osmedeus v5 | ✱ | Go server+workers, Redis queue | YAML flows w/ decision routing, hooks | workflow diagram UI | A: YAML-first confirmed; P: workflow diagram |
| 4 | DeepBounty | – | FastAPI master + isolated workers | queue consumer groups | basic | A: core architecture already mirrors it |
| 5 | reconFTW | ✱ | bash pipeline, modular phases | enum→probe→vuln→attack | text reports, AI report option | R: shell pipeline (no sandbox); A: AI-report idea |
| 6 | AutoAR | – | recon automation | staged | minimal | R: nothing beyond existing |
| 7 | recon-pipeline | – | CLI stages | linear | none | R: linear-only |
| 8 | Bug-Bounty-recon | – | scripts | linear | none | R |
| 9 | bb-engine | – | Rust engine | baseline diff FP-reduction | none | A: confidence/dedup model already in schema |

## 2. Vulnerability management

| # | System | ✱ | Architecture | Correlation | UI | Take |
|---|---|---|---|---|---|---|
| 10 | DefectDojo | ✱ | Django, ASPM | dedup engine, fingerprints | rich dashboards, RBAC | A: fingerprint dedup already; P: finding aging/SLA later |
| 11 | Faraday | ✱ | server/client, 80+ plugins | vuln correlation workspace | collaborative web UI | A: plugin-count ambition; P: import plugins |
| 12 | ArcherySec | ✱ | Django | scanner XML imports | dashboards | R: importer-first design; ours is execution-first |
| 13 | Reconmap | – | PHP ops platform | tasks/reports | ops views | A: ops-view language |
| 14 | GVMD/OpenVAS | – | manager/scanner split | NVT feed | Greenbone UI | R: heavy; A: feed-update discipline idea |
| 15 | Vuls | ✱ | agentless Go scanner | CVE DB mapping | TUI/VulsRepo | P: CVE-mapping of findings later |
| 16 | Sublert-class monitors | – | monitor | state diff | simple | A: is_new diffing already |

## 3. Recon & scanning tools (integration surface)

| # | Tool | ✱ | Category | Our status |
|---|---|---|---|---|
| 17 | subfinder | ✱ | passive subdomains | integrated |
| 18 | assetfinder | – | passive subdomains | integrated |
| 19 | amass | – | deep enum | registered, optional step |
| 20 | massdns | ✱(tests) | DNS resolve filter | integrated (routing gate) |
| 21 | dnsx | – | DNS toolkit | allowed |
| 22 | httpx | ✱ | host probing | integrated (+signal emission) |
| 23 | naabu | ✱ | port scan | integrated |
| 24 | nmap | ✱ | service enum | targeted-only via gate |
| 25 | nuclei | ✱ | template vulns | integrated; P: workflow-template mode |
| 26 | katana | ✱ | crawler | integrated |
| 27 | waybackurls | – | archive URLs | integrated |
| 28 | uncover | – | multi-engine search | allowed (needs keys) |
| 29 | ffuf | ✱ | content discovery | integrated (batch) |
| 30 | arjun | ✱ | param mining | integrated |
| 31 | sqlmap | ✱ | sqli validation | gated, conservative caps |
| 32 | trufflehog | ✱ | secrets | integrated (redacted) |
| 33 | dalfox | ✱ | XSS | gated on url_param |
| 34 | gowitness | – | screenshots | capability present |
| 35 | interactsh | ✱ | OOB collaborator | built-in driver (RSA-OAEP+AES) |
| 36 | OneForAll | ✱ | subdomain suite | R: overlaps; P: CT-log module idea |
| 37 | FinalRecon | ✱ | all-in-one web recon | P: single-wrapper header/ssl checks |
| 38 | sn0int | ✱ | OSINT framework+sandbox | A: sandbox concept validates wrapper model |
| 39 | theHarvester-class OSINT | – | emails/osint | P: future finding type `email` |
| 40 | wpscan | – | WordPress | routed gate exists |
| 41 | corsy | – | CORS | routed gate exists |
| 42 | bypass-403 tooling | – | 403 bypass | routed gate exists |
| 43 | takeover-checker class | – | subdomain takeover | P: new wrapper candidate |

## 4. Infra/scale & notification layers

| # | System | ✱ | Idea | Take |
|---|---|---|---|---|
| 44 | Ax framework | ✱ | cloud fleet elasticity (9 providers) | R now (credential surface), revisit per PERFORMANCE.md trigger |
| 45 | notify (projectdiscovery) | ✱ | Slack/Discord/Telegram/Teams/custom webhooks | A: hub matches custom-webhook model; P: provider adapters |
| 46 | Nettacker | ✱ | OWASP framework, scheduled scans, API-key Web UI | A: scheduling backlog item |
| 47 | PentestGPT / hackingBuddyGPT | ✱/– | LLM agents gated by deterministic contracts | A: MCP gateway = same principle live |
| 48 | Spiderfoot (BBOT inspiration) | – | event correlation graph | P: graph viz |
| 49 | Zero-FP 4-agent model | – | evidence-gated progression | A: validation_state lifecycle live |
| 50 | arkadiyt/bug-bounty-targets | – | structured program scope feeds | A: import_scope.py consumes this format |

## Key gaps identified → actions taken now

1. **Passive scan preset missing** (reNgine ships 4+ ready engines) → added
   `workflows/passive.yaml` + guard test proving it stays non-intrusive.
2. **Ops dashboard lacked severity backlog / fleet view / activity feed /
   launcher** (reNgine, Osmedeus, DefectDojo are far richer) → dashboard
   overhaul + `GET /api/v1/workers` + enriched `/api/v1/dashboard`
   (severity histogram + audit tail in the same single round-trip).
3. **Scan launch required curl** → one-click launcher in the UI with inline
   scope-decision feedback.
4. **No live health indicator** → readyz status dot in the header.
5. **Fixed-rate polling only** → selectable interval (2s–60s) + pause.

## Follow-ups (deliberately not done now)

* Workflow-diagram visualization (Osmedeus v5 style).
* Scheduled/clocked scans (reNgine periodic scans; Nettacker scheduling).
* Notification provider adapters beyond the generic webhook (notify parity).
* Finding→CVE mapping and finding aging/SLA columns (DefectDojo/Vuls ideas).
* Import plugins for external scanner report formats (Faraday-style).

