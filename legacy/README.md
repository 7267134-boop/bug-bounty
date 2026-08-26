# Legacy — Stage 0 (superseded single-host orchestrator)

This directory preserves the original single-host orchestrator
(`orchestrator.py` + `recon/` package) that predates the distributed
platform in [`platform/`](../../platform).

**It is kept for historical reference only.** It is NOT part of the platform:
no scope gates, no worker isolation, no audit trail. Do not extend it.

Run its (still-green) test suite from this directory:

```bash
cd legacy/stage0
python -m pytest tests -q
```
