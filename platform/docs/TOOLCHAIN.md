# Toolchain Decisions — Keep / Merge / Exclude (Stage 2)

Every tool below was evaluated against our wrapper contract
(`consumes`/`produces`, argv-only, sandboxed). "Keep" = wrapped in
`worker/tools/`. Decisions favor zero functional overlap.

## Kept & wrapped

| Tool | Role | Consumes → Produces | Notes |
|---|---|---|---|
| subfinder | Passive enum (primary) | – → subdomain | `-json`; provider keys via passthrough env |
| assetfinder | Cheap secondary enum | – → subdomain | high-frequency runs, near-zero cost |
| amass | Deep passive enum (optional) | – → subdomain | slow; results filtered to program namespace |
| dnsx | Resolution + wildcard filter | subdomain → ip | `-json -resp` |
| httpx | Live-web probe/enrichment | subdomain → live_host | JSON: url/status/title/tech/webserver |
| naabu | Port discovery | ip,subdomain → open_port | connect scan (`-s connect`) for unprivileged container; CDN exclusion |
| waybackurls | Historic URL mining | subdomain → archive_url,url_param | stdin-fed via executor |
| katana | Active crawling (standard mode) | live_host → url,url_param | headless deferred (no Chrome in image) |
| nuclei | Vuln detection | live_host → vulnerability | severity-filtered; templates via `nuclei -ut` at image init |
| uncover | Shodan/Censys/… exposure search | – → subdomain,open_port | **results filtered to program namespace** before ingest |

## Excluded (overlap with kept tools)

| Excluded | Replaced by | Reason |
|---|---|---|
| OneForAll | subfinder+amass+assetfinder | Python-heavy monolith duplicating all three |
| Sublist3r | subfinder | unmaintained, weaker sources |
| gau / hakrawler | waybackurls / katana | functional subsets |
| httprobe | httpx | superseded by its own inspiration |
| masscan / RustScan / MassDNS / puredns / shuffledns | naabu / dnsx | same niche; fewer binaries to maintain |
| gobuster / dirsearch / feroxbuster | ffuf *(Stage 4)* | one content-discovery engine |
| ParamSpider | waybackurls (`url_param` split) | param URLs already extracted |
| gf / anew / mapcidr / dnsgen | native Python (findings store/ipaddress/dnsx perms) | trivial logic absorbed into platform |

## Deferred to later stages (planned wrappers)

- **Stage 3**: wafw00f (WAF signal before aggressive steps), cdncheck.
- **Stage 4**: ✅ **LANDED** (`worker/tools/focused.py`, `focused_scan.py`,
  `focused.py`, `oob_tools.py`; chain: `workflows/focused.yaml`):
    * `ffuf` + bundled fallback wordlist (SecLists via `params.wordlist`)
      → `live_host` → `discovered_url` (content discovery);
    * `arjun` → `live_host`/`api_surface` → `url_param` (hidden parameters);
    * `sqlmap` → `url_param` only, conservative level=1/risk=1, batch-capped;
    * `trufflehog` → `js_url` sweep; hits REDACTED before storage
      (detector + location + 12-char preview, never the secret itself);
    * `dalfox` / `gowitness` (see above);
    * `interactsh` → builtin Python collaborator client
      (`worker/tools/drivers/interactsh.py`) implementing the
      projectdiscovery protocol natively: RSA-OAEP registration, unique
      per-parameter callback hosts, CTR/CFB dual-mode poll decryption,
      token-correlated blind-SSRF findings. No extra binary needed.
      Enable with `interactsh` in `WORKER_CAPABILITIES`.
  Still deferred: secretfinder/linkfinder (JS parsing), tlsx/testssl.sh.
- **Stage 5**: ✅ **LANDED** — `mcp_server/`: stdio JSON-RPC MCP gateway;
  six typed tools proxied to the Master API; triage structurally excluded
  (human-only); no DB/Redis access, no shell, no inbound ports.
- **Stage 6**: ✅ **LANDED** — `master/reporting.py` +
  `GET /api/v1/scans/{id}/report`: validated+new filter enforced in SQL;
  executive summary; severity-ranked findings with CVSS; safe PoC cURL
  (allowlisted URLs, no metacharacters); Markdown + JSON renderers; exposed
  to agents via the MCP `get_scan_report` tool.

## Security invariants preserved

* argv-list execution only; no shell interpolation anywhere.
* Provider API keys reach tool processes solely via explicit
  `WORKER_ENV_PASSTHROUGH` allowlist.
* uncover/amass outputs are namespace-filtered before becoming findings —
  out-of-scope assets can never enter the pipeline even if a tool emits them.

## Stage 3 update (decision engine live)

New kept wrappers (see `worker/tools/routing_tools.py`, `recon_probe.py`):
`massdns` (R1 dead-domain filter), `nmap` (R2 targeted `-sV -sC`),
`routing.bypass403` (R4), `wpscan` (R5), `corsy` (R6).
New producer signals: httpx → `http_403`, `login_page`, `api_surface`,
`wordpress`; katana/waybackurls → `js_url`; nmap → `exposed_service`.
Chain: `workflows/deep-recon.yaml`. kiterunner remains deferred
(archived upstream; ffuf + API wordlists cover the need).
