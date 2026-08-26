# Bug Bounty Reconnaissance Orchestrator

A highly configurable, Python-based automated recon orchestrator that runs
**natively on Kali Linux** (no Docker), executes industry-standard security
tools via OS subprocesses, retries failing tools (default: 3 attempts), and
outputs **dual-format reports**: a human-readable Markdown summary plus a
detailed machine-parseable JSON log for downstream AI/automation.

## Supported Tools

| Tool | Stage | Purpose |
|---|---|---|
| `subfinder` | 1 | Passive subdomain enumeration |
| `assetfinder` | 1 | Subdomain discovery (CT logs) |
| `amass` | 1 | OWASP Amass passive enumeration |
| `nmap` | 1 | Service/version scan, top-1000 ports |
| `naabu` | 1 | Fast port scanning |
| `httpx` | 2 | Probe discovered subdomains for live web services |
| `nuclei` | 3 | Template-driven vulnerability scanning on live hosts |

Stage 1 tools run in parallel; stage 2 consumes stage-1 output
(`context_subdomains.txt`); stage 3 consumes stage-2 output
(`context_live_hosts.txt`).

## Installation (Kali Linux)

```bash
# Security tools are assumed to be in $PATH already:
sudo apt install nmap amass        # or go install projectdiscovery tools
pip install -r requirements.txt
```

## Usage

```bash
# Simplest scan (all tools):
python orchestrator.py -t example.com

# Select specific tools:
python orchestrator.py -t example.com --tools subfinder,httpx,nuclei

# Via JSON config file (see config.example.json):
python orchestrator.py --config scan.json

# Full customization:
python orchestrator.py -t example.com \
    --tools all \
    --max-retries 3 \
    --timeout 3600 \
    --concurrency 3 \
    --output-dir /opt/reports \
    --verbosity low

# Validate tool availability without executing scans:
python orchestrator.py -t example.com --dry-run
```

CLI flags override the JSON config file, which overrides defaults.

## Outputs

```
reports/
├── {domain}_{timestamp}_full_log.json   # machine-parseable (AI/automation)
├── {domain}_{timestamp}_summary.md      # human-readable summary
└── logs/
    ├── orchestrator.log                 # rotating DEBUG app log
    └── {domain}/                        # 100% raw tool output, always preserved
        ├── subfinder_20260825_120000.log
        ├── context_subdomains.txt       # stage hand-off files
        └── ...
```

### Unified Vulnerability Schema (per tool run)

```json
{
  "target": "example.com",
  "tool_name": "nuclei",
  "execution_time_sec": 42.1,
  "status": "success | failed | skipped",
  "findings": ["...parsed objects..."],
  "raw_log_reference": "/abs/path/to/raw/log",
  "retries_used": 1,
  "return_code": 0,
  "error_summary": ""
}
```

## Behavior Guarantees

* **Never halts the pipeline**: a tool failing after `max_retries` is marked
  `failed` and the scan continues.
* **100% raw-log retention**: STDOUT/STDERR of every attempt are written to
  disk even when parsing fails or the tool crashes.
* **Timeout enforcement**: each attempt is bounded by `tool_timeout_sec`;
  hung processes are killed and retried.
* **Disk-full safety**: write errors raise a handled error, alert the user,
  and terminate gracefully.
* **Dry-run mode**: verifies binaries exist in `$PATH` without executing them.

## Tests

```bash
python -m pytest tests/ -v
```

Tests use mock subprocesses (`sys.executable`) so they run without any Kali
tools installed, including the acceptance test: *both reports are generated
even when a tool fails 100% of the time.*

## Scope

Reconnaissance and vulnerability scanning only — no active exploitation.
