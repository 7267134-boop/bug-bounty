"""Recon pipeline orchestrator.

Executes tool stages in dependency order, running independent tools within a
stage in parallel via asyncio. Handles missing binaries (skip + mark failed),
disk-full conditions (graceful shutdown) and dry-run validation.
"""

from __future__ import annotations

import asyncio
import logging
import logging.handlers
import os
import time
from typing import Any

from .config import ScanConfig
from .reports import ReportGenerator
from .runner import DiskFullError, ToolRunner, ToolResult
from .tools import ToolSpec, expand_tool_selection

logger = logging.getLogger("orchestrator.engine")

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "unknown")


def setup_logging(output_dir: str, verbosity: str) -> str:
    """Configure the rotating application log; returns its path."""
    log_dir = os.path.join(os.path.abspath(output_dir), "logs")
    os.makedirs(log_dir, exist_ok=True)
    app_log = os.path.join(log_dir, "orchestrator.log")
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    handler = logging.handlers.RotatingFileHandler(
        app_log, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-8s %(name)s :: %(message)s")
    )
    root.addHandler(handler)
    console_level = logging.INFO if verbosity == "high" else logging.WARNING
    console = logging.StreamHandler()
    console.setLevel(console_level)
    console.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root.addHandler(console)
    return app_log


class ReconOrchestrator:
    """Top-level pipeline coordinator."""

    def __init__(self, config: ScanConfig, ui=None):
        self.config = config
        self.ui = ui
        self.output_dir = os.path.abspath(config.output_dir)
        self.log_root = os.path.join(self.output_dir, "logs", config.target_domain)

    # ------------------------------------------------------------------ #
    async def run(self) -> dict[str, Any]:
        """Execute the full pipeline and return the aggregated report data."""
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")
        specs = expand_tool_selection(self.config.enabled_tools)
        logger.info(
            "pipeline start: target=%s tools=%s",
            self.config.target_domain, [s.name for s in specs],
        )

        results: list[ToolResult] = []
        ctx: dict[str, Any] = {"files": {}, "subdomains": [], "live_hosts": []}

        if self.config.dry_run:
            results.extend(self._dry_run(specs))
            report = self._build_report(timestamp, results)
            report["output_files"] = self._write_reports(report)
            return report

        max_stage = max(s.stage for s in specs)
        for stage in range(1, max_stage + 1):
            stage_specs = [s for s in specs if s.stage == stage]
            if not stage_specs:
                continue
            logger.info("stage %d: %s", stage, [s.name for s in stage_specs])
            stage_results = await self._run_stage(stage_specs, ctx)
            results.extend(stage_results)
            self._update_context(stage_results, ctx)

        report = self._build_report(timestamp, results)
        # DiskFullError intentionally propagates so the CLI can gracefully stop.
        report["output_files"] = self._write_reports(report)
        logger.info("pipeline complete: %s", report["output_files"])
        return report

    # ------------------------------------------------------------------ #
    async def _run_stage(self, specs: list[ToolSpec], ctx: dict[str, Any]) -> list[ToolResult]:
        semaphore = asyncio.Semaphore(self.config.concurrency)

        async def run_one(spec: ToolSpec) -> ToolResult:
            missing = [f for f in spec.requires_files if not ctx["files"].get(f)]
            if missing:
                logger.warning("skipping %s: missing upstream inputs %s", spec.name, missing)
                now = time.time()
                return ToolResult(
                    target=self.config.target_domain,
                    tool_name=spec.name,
                    execution_time_sec=0.0,
                    status="skipped",
                    findings=[],
                    raw_log_reference="",
                    error_summary=f"missing upstream input files: {missing}",
                    started_at=now,
                    ended_at=now,
                )
            async with semaphore:
                if self.ui:
                    self.ui.tool_started(spec.name)
                runner = ToolRunner(spec, self.config, self.log_root, ui=self.ui)
                result = await runner.run(ctx)
                if self.ui:
                    self.ui.tool_finished(result)
                return result

        return list(await asyncio.gather(*(run_one(s) for s in specs)))

    def _update_context(self, results: list[ToolResult], ctx: dict[str, Any]) -> None:
        """Aggregate stage findings into context files for downstream tools."""
        from .runner import write_text_file

        for result in results:
            for finding in result.findings:
                ftype = finding.get("type")
                if ftype == "subdomain":
                    sub = finding.get("subdomain")
                    if sub and sub not in ctx["subdomains"]:
                        ctx["subdomains"].append(sub)
                elif ftype == "live_host":
                    url = finding.get("url")
                    if url and url not in ctx["live_hosts"]:
                        ctx["live_hosts"].append(url)

        if ctx["subdomains"] and "subdomains" not in ctx["files"]:
            path = os.path.join(self.log_root, "context_subdomains.txt")
            write_text_file(path, "\n".join(ctx["subdomains"]) + "\n")
            ctx["files"]["subdomains"] = path
        if ctx["live_hosts"] and "live_hosts" not in ctx["files"]:
            path = os.path.join(self.log_root, "context_live_hosts.txt")
            write_text_file(path, "\n".join(ctx["live_hosts"]) + "\n")
            ctx["files"]["live_hosts"] = path

    def _dry_run(self, specs: list[ToolSpec]) -> list[ToolResult]:
        """Validate tool availability in $PATH without executing anything."""
        results = []
        now = time.time()
        for spec in specs:
            resolved = spec.resolve_binary()
            ok = resolved is not None
            if self.ui:
                self.ui.dry_run_status(spec.name, resolved)
            results.append(
                ToolResult(
                    target=self.config.target_domain,
                    tool_name=spec.name,
                    execution_time_sec=0.0,
                    status="success" if ok else "failed",
                    findings=[],
                    raw_log_reference=os.path.join(self.log_root, "(dry-run: no execution)"),
                    error_summary="" if ok else f"{spec.binary} not found in $PATH",
                    started_at=now,
                    ended_at=now,
                )
            )
        return results

    def _build_report(self, timestamp: str, results: list[ToolResult]) -> dict[str, Any]:
        vulns = sorted(
            (f for r in results for f in r.findings if f.get("type") == "vulnerability"),
            key=lambda v: SEVERITY_ORDER.index(v.get("severity", "unknown"))
            if v.get("severity", "unknown") in SEVERITY_ORDER else len(SEVERITY_ORDER),
        )
        metrics = {
            "tools_total": len(results),
            "tools_success": sum(1 for r in results if r.status == "success"),
            "tools_failed": sum(1 for r in results if r.status == "failed"),
            "tools_skipped": sum(1 for r in results if r.status == "skipped"),
            "total_execution_time_sec": round(sum(r.execution_time_sec for r in results), 3),
            "retry_counts": {r.tool_name: r.retries_used for r in results},
            "findings_count": sum(len(r.findings) for r in results),
            "vulnerabilities_count": len(vulns),
            "vulnerabilities_by_severity": {
                sev: sum(1 for v in vulns if v.get("severity") == sev)
                for sev in ("critical", "high", "medium", "low", "info")
            },
        }
        return {
            "schema_version": "1.0",
            "generated_at": timestamp,
            "target_domain": self.config.target_domain,
            "config": self.config.to_dict(),
            "metrics": metrics,
            "results": [r.to_dict() for r in results],
            "vulnerabilities": vulns,
        }

    def _write_reports(self, report: dict[str, Any]) -> dict[str, str]:
        generator = ReportGenerator(self.output_dir, report["generated_at"])
        json_path = generator.write_json(report)
        md_path = generator.write_markdown(report)
        return {"json_report": json_path, "markdown_summary": md_path}


