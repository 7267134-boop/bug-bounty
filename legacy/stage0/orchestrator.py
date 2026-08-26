#!/usr/bin/env python3
"""Bug Bounty Reconnaissance Orchestrator - CLI entry point.

Native Kali Linux execution: runs standard security tools via OS subprocesses,
retries failing tools up to N times, never halts the pipeline on a single tool
failure, and produces dual-format reports (Markdown for humans, JSON for AI).

Usage examples:
    python orchestrator.py -t example.com
    python orchestrator.py -t example.com --tools nmap,subfinder,nuclei --verbosity low
    python orchestrator.py --config scan.json
    python orchestrator.py -t example.com --dry-run
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from recon.config import ConfigError, build_config
from recon.engine import ReconOrchestrator, setup_logging
from recon.runner import DiskFullError
from recon.tools import TOOL_SPECS, expand_tool_selection

console = Console()
EXIT_OK = 0
EXIT_CONFIG_ERROR = 400  # mirrors HTTP 400 per spec
EXIT_RUNTIME_ERROR = 1


class RichUI:
    """Live terminal interface: progress bar + per-tool status + verbosity-aware echo."""

    def __init__(self, total_tools: int):
        self.progress = Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[bold blue]{task.description}[/]"),
            BarColumn(bar_width=30),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
        )
        self.overall = self.progress.add_task("Overall progress", total=total_tools)
        self.statuses: dict[str, str] = {}
        self._live: Live | None = None

    def __enter__(self) -> "RichUI":
        self._live = Live(self.progress, console=console, refresh_per_second=4)
        self._live.start()
        return self

    def __exit__(self, *exc) -> None:
        if self._live:
            self._live.stop()

    # ---- callbacks invoked by the engine / runner ----
    def tool_started(self, tool_name: str) -> None:
        self.statuses[tool_name] = "running"
        self._refresh()

    def update_status(self, tool_name: str, status: str) -> None:
        self.statuses[tool_name] = status
        self._refresh()

    def tool_finished(self, result) -> None:
        icon = {"success": "[green]\u2713[/]", "failed": "[red]\u2717[/]", "skipped": "[yellow]-[/]"}
        self.statuses[result.tool_name] = (
            f"{icon.get(result.status, result.status)} "
            f"{len(result.findings)} findings in {result.execution_time_sec:.1f}s"
        )
        self.progress.advance(self.overall)
        self._refresh()

    def echo_line(self, tool_name: str, line: str) -> None:
        """Live STDOUT tailing (only active at high verbosity)."""
        console.print(f"  [dim]\\[{tool_name}][/dim] {line[:200]}")

    def dry_run_status(self, tool_name: str, resolved_path: str | None) -> None:
        mark = f"[green]OK[/green] ({resolved_path})" if resolved_path else "[red]MISSING[/red]"
        console.print(f"  [bold]{tool_name:<14}[/bold] {mark}")

    def _refresh(self) -> None:
        if not self.statuses or not self._live:
            return
        table = Table.grid(padding=(0, 2))
        table.add_column(style="bold cyan", justify="right")
        table.add_column()
        for name, status in self.statuses.items():
            table.add_row(name, str(status))
        render = Panel(table, title="[bold]Tool Status[/bold]", border_style="dim")
        self._live.update(render)



def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="orchestrator",
        description="Native Kali Linux bug bounty reconnaissance orchestrator.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-t", "--target", dest="target_domain",
                        help="Target domain (e.g. example.com)")
    parser.add_argument("--config", help="Path to JSON configuration file")
    parser.add_argument(
        "--tools",
        help=f"Comma-separated tools to run, or 'all'. Available: {', '.join(sorted(TOOL_SPECS))}, all",
    )
    parser.add_argument("--max-retries", type=int, default=None,
                        help="Maximum attempts per tool before marking it failed (default: 3)")
    parser.add_argument("--timeout", type=int, default=None, dest="tool_timeout_sec",
                        help="Per-tool timeout in seconds (default: 3600)")
    parser.add_argument("--concurrency", type=int, default=None,
                        help="Max tools running in parallel within a stage (default: 3)")
    parser.add_argument("--output-dir", default=None,
                        help="Directory for reports/logs (default: ./reports)")
    parser.add_argument("-v", "--verbosity", choices=["high", "low"], default=None,
                        help="'high' tails tool STDOUT live; 'low' shows summary only")
    parser.add_argument("--dry-run", action="store_true",
                        help="Validate tool availability in $PATH without executing scans")
    return parser.parse_args(argv)


async def async_main(args: argparse.Namespace) -> int:
    try:
        config = build_config(cli_args=args, json_path=args.config)
    except ConfigError as exc:
        console.print(f"[bold red][CONFIG ERROR][/] {exc}")
        return EXIT_CONFIG_ERROR

    app_log = setup_logging(config.output_dir, config.verbosity)

    try:
        specs = expand_tool_selection(config.enabled_tools)
    except KeyError as exc:
        console.print(
            f"[bold red][CONFIG ERROR][/] Unknown tool: {exc}. "
            f"Available: {', '.join(sorted(TOOL_SPECS))}"
        )
        return EXIT_CONFIG_ERROR

    banner = Panel(
        f"[bold]Target:[/]  {config.target_domain}\n"
        f"[bold]Tools:[/]   {', '.join(s.name for s in specs)}\n"
        f"[bold]Retries:[/] {config.max_retries}   [bold]Timeout:[/] {config.tool_timeout_sec}s   "
        f"[bold]Verbosity:[/] {config.verbosity}\n"
        f"[bold]Reports:[/] {config.output_dir}\n"
        f"[bold]App log:[/]  {app_log}",
        title="Bug Bounty Recon Orchestrator",
        border_style="bright_blue",
    )
    console.print(banner)

    ui = RichUI(total_tools=len(specs))
    orchestrator = ReconOrchestrator(config, ui=ui)
    try:
        with ui:
            report = await orchestrator.run()
    except DiskFullError as exc:
        console.print(f"\n[bold red][DISK FULL][/] {exc}")
        console.print("Gracefully terminating to prevent system corruption. Raw logs preserved.")
        return EXIT_RUNTIME_ERROR
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user - shutting down gracefully.[/yellow]")
        return 130

    _print_summary(report, config.dry_run)
    return EXIT_OK


def _print_summary(report: dict, dry_run: bool) -> None:
    m = report.get("metrics", {})
    table = Table(title="Scan Summary", show_header=True, header_style="bold magenta")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Target", report.get("target_domain", "?"))
    table.add_row("Tools success / failed / skipped",
                  f"{m.get('tools_success', 0)} / {m.get('tools_failed', 0)} "
                  f"/ {m.get('tools_skipped', 0)}")
    table.add_row("Findings total", str(m.get("findings_count", 0)))
    sev = m.get("vulnerabilities_by_severity", {})
    table.add_row(
        "Vulns (crit/high/med/low/info)",
        f"{sev.get('critical', 0)} / {sev.get('high', 0)} / {sev.get('medium', 0)} "
        f"/ {sev.get('low', 0)} / {sev.get('info', 0)}",
    )
    console.print(table)

    out = report.get("output_files", {})
    if dry_run:
        missing = [r["tool_name"] for r in report.get("results", []) if r["status"] == "failed"]
        if missing:
            console.print(f"[yellow]Missing binaries:[/] {', '.join(missing)}")
        else:
            console.print("[green]All selected tools are available in $PATH.[/green]")
    if out:
        console.print(f"[green]JSON full log:[/] {out.get('json_report')}")
        console.print(f"[green]MD summary:[/]    {out.get('markdown_summary')}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if not args.target_domain and not args.config:
        console.print("[bold red][ERROR][/] A target is required: use -t/--target or --config.")
        return EXIT_CONFIG_ERROR
    try:
        return asyncio.run(async_main(args))
    except ConfigError as exc:  # raised in rare post-logging paths
        console.print(f"[bold red][CONFIG ERROR][/] {exc}")
        return EXIT_CONFIG_ERROR


if __name__ == "__main__":
    sys.exit(main())

