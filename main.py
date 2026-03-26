#!/usr/bin/env python3
"""
BakiBounty - Advanced Bug Bounty Automation Framework

CLI entry point built with Typer + Rich.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

# Load .env file before other imports
from dotenv import load_dotenv

load_dotenv()

import typer
import yaml
from rich.panel import Panel
from rich.table import Table

from config.schema import BakiConfig
from utils.helpers import resolve_all_tools
from utils.logger import console, setup_logging

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="bakibounty",
    help="Advanced bug bounty automation framework.",
    no_args_is_help=True,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
)

# Subcommand groups
recon_app = typer.Typer(help="Reconnaissance modules (subfinder, amass, etc.)")
probe_app = typer.Typer(help="HTTP probing and technology detection")
discover_app = typer.Typer(help="Content and endpoint discovery")
scan_app = typer.Typer(help="Vulnerability scanning (nuclei, ffuf, etc.)")
app.add_typer(recon_app, name="recon", rich_help_panel="Modules")
app.add_typer(probe_app, name="probe", rich_help_panel="Modules")
app.add_typer(discover_app, name="discover", rich_help_panel="Modules")
app.add_typer(scan_app, name="scan", rich_help_panel="Modules")


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------


def load_config(config_path: Optional[Path] = None) -> BakiConfig:
    """Load and validate YAML config into a Pydantic model."""
    candidates = [
        config_path,
        Path("config/config.yaml"),
        Path("config/config.yml"),
    ]

    for path in candidates:
        if path and path.is_file():
            with open(path, "r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh) or {}
            return BakiConfig.model_validate(raw)

    # Fallback to defaults
    console.print("[dim]No config file found -- using defaults.[/dim]")
    return BakiConfig()


# ---------------------------------------------------------------------------
# Shared options callback
# ---------------------------------------------------------------------------


def version_callback(value: bool) -> None:
    if value:
        console.print("[bold cyan]BakiBounty[/bold cyan] v0.1.0")
        raise typer.Exit()


# ---------------------------------------------------------------------------
# Root command
# ---------------------------------------------------------------------------


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    config: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to config YAML file.",
        rich_help_panel="Global",
    ),
    target: Optional[str] = typer.Option(
        None, "--target", "-t", help="Target domain.", rich_help_panel="Global"
    ),
    output_dir: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output directory.", rich_help_panel="Global"
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose output.",
        rich_help_panel="Global",
    ),
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        callback=version_callback,
        is_eager=True,
        help="Show version.",
        rich_help_panel="Global",
    ),
) -> None:
    """
    [bold cyan]BakiBounty[/bold cyan] -- Bug bounty automation framework.

    Run [bold]bakibounty [COMMAND] --help[/bold] for module usage.
    """
    # Load config
    cfg = load_config(config)

    # CLI overrides
    if verbose:
        cfg.general.verbose = True
    if output_dir:
        cfg.output.dir = output_dir

    # Setup logging
    setup_logging(log_dir=cfg.output.dir, verbose=cfg.general.verbose)

    # Store config in context for subcommands
    ctx.ensure_object(dict)
    ctx.obj["config"] = cfg
    ctx.obj["target"] = target

    # Show banner if no subcommand
    if ctx.invoked_subcommand is None:
        _print_banner(cfg)


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------


def _print_banner(cfg: BakiConfig) -> None:
    banner = """
[bold cyan]
    ____        __                  ____
   / __ )____ _/ /_____  ________  / __ )__  __________  _____
  / __  / __ `/ //_/ _ \\/ ___/ _ \\/ __  / / / / ___/ _ \\/ ___/
 / /_/ / /_/ / ,< /  __/ /  /  __/ /_/ / /_/ / /  /  __/ /
/_____/\\__,_/_/|_|\\___/_/   \\___/_____/\\__,_/_/   \\___/_/
[/bold cyan]
[bold white]Bug Bounty Automation Framework[/bold white]
[dim]v0.1.0 -- recon | probe | discover | scan | report[/dim]
"""
    console.print(Panel(banner, border_style="cyan", padding=(1, 2)))

    # Config summary table
    table = Table(title="Configuration", show_header=False, border_style="dim")
    table.add_column("Key", style="bold")
    table.add_column("Value")
    table.add_row("Threads", str(cfg.general.threads))
    table.add_row("Rate Limit", f"{cfg.general.rate_limit} req/s")
    table.add_row("Timeout", f"{cfg.general.timeout}s")
    table.add_row("Output Dir", str(cfg.output.dir))
    table.add_row("Formats", ", ".join(f.value for f in cfg.output.formats))
    table.add_row("Notifications", "ON" if cfg.notifications.enabled else "OFF")
    console.print(table)


# ---------------------------------------------------------------------------
# Commands -- Pipeline
# ---------------------------------------------------------------------------


@app.command(rich_help_panel="Pipeline")
def run(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Target domain or file with targets."),
    full: bool = typer.Option(
        False,
        "--full",
        "-f",
        help="Run full pipeline (recon > probe > discover > scan).",
    ),
    skip_recon: bool = typer.Option(False, "--skip-recon", help="Skip recon phase."),
    skip_scan: bool = typer.Option(False, "--skip-scan", help="Skip scanning phase."),
    concurrency: int = typer.Option(
        3,
        "--concurrency",
        "-j",
        help="Max parallel targets (1 = sequential).",
    ),
) -> None:
    """Run the automated pipeline against a [bold]TARGET[/bold]."""
    import asyncio

    cfg: BakiConfig = ctx.obj["config"]
    setup_logging(log_dir=cfg.output.dir, verbose=cfg.general.verbose)

    from loguru import logger
    from rich.live import Live
    from rich.table import Table as RichTable

    from modules.discovery import run_discovery
    from modules.probing import run_probing
    from modules.recon import run_recon
    from modules.scanner import run_scanner
    from utils.helpers import create_run_dir, parse_targets
    from utils.notify import notify_finding, notify_summary
    from utils.report import generate_report

    targets = parse_targets(target)
    if not targets:
        console.print("[red]No targets found.[/red]")
        raise typer.Exit(1)

    # Build execution plan
    phases: list[str] = []
    if not skip_recon:
        phases.append("recon")
    phases.append("probe")
    phases.append("discover")
    if not skip_scan:
        phases.append("scan")
    phases.append("report")

    mode = "parallel" if concurrency > 1 and len(targets) > 1 else "sequential"
    logger.info(
        "Pipeline started: {} target(s), {} (j={})",
        len(targets),
        mode,
        concurrency,
    )

    console.print(f"\n[bold cyan]>>> Pipeline[/bold cyan] {len(targets)} target(s)")
    console.print(f"[dim]Phases: {' >> '.join(phases)}[/dim]")
    if concurrency > 1 and len(targets) > 1:
        console.print(f"[dim]Concurrency: {concurrency}[/dim]")
    console.print()

    # --- Per-target pipeline ---
    async def _run_single_target(t: str, sem: asyncio.Semaphore) -> dict:
        """Run full pipeline for one target. Returns summary dict."""
        async with sem:
            run_dir = create_run_dir(t, base_dir=cfg.output.dir)
            summary: dict = {
                "target": t,
                "run_dir": run_dir,
                "status": "success",
                "subdomains": 0,
                "alive": 0,
                "endpoints": 0,
                "findings": 0,
                "duration": 0.0,
                "errors": [],
            }
            import time as _time

            start = _time.monotonic()

            try:
                for phase in phases:
                    if phase == "recon":
                        r = await run_recon(t, cfg, run_dir=run_dir)
                        summary["subdomains"] = r.item_count
                        if r.errors:
                            summary["errors"].extend(r.errors)

                    elif phase == "probe":
                        r = await run_probing(t, cfg, run_dir=run_dir)
                        summary["alive"] = r.item_count
                        if r.errors:
                            summary["errors"].extend(r.errors)

                    elif phase == "discover":
                        r = await run_discovery(t, cfg, run_dir=run_dir)
                        summary["endpoints"] = r.item_count
                        if r.errors:
                            summary["errors"].extend(r.errors)

                    elif phase == "scan":
                        r = await run_scanner(t, cfg, run_dir=run_dir)
                        summary["findings"] = r.item_count
                        if r.status in ("critical", "high"):
                            summary["status"] = r.status
                        if r.errors:
                            summary["errors"].extend(r.errors)

                        # AI analysis of findings
                        if cfg.ai.enabled and r.items:
                            from utils.ai import analyze_findings_batch, is_enabled

                            if is_enabled(cfg):
                                r.items = await analyze_findings_batch(r.items, cfg)
                                # Re-save with AI analysis
                                from utils.helpers import save_json

                                save_json(r.to_dict(), run_dir / "scanner.json")

                        # Send notifications for matching findings
                        if cfg.notifications.enabled and r.items:
                            for finding in r.items:
                                await notify_finding(finding, t, cfg)
                            await notify_summary(t, r.items, r.duration, cfg)

                    elif phase == "report":
                        fmts = [f.value for f in cfg.output.formats]
                        generate_report(run_dir, formats=fmts)

            except Exception as exc:
                summary["status"] = "failed"
                summary["errors"].append(str(exc))
                logger.error("Target {} failed: {}", t, exc)

            summary["duration"] = round(_time.monotonic() - start, 1)
            return summary

    # --- Progress table builder ---
    def _build_table(results: list[dict], in_progress: set[str]) -> RichTable:
        """Build a live progress table."""
        tbl = RichTable(title="Pipeline Progress", border_style="cyan")
        tbl.add_column("Target", style="bold", no_wrap=True)
        tbl.add_column("Status")
        tbl.add_column("Subs", justify="right")
        tbl.add_column("Alive", justify="right")
        tbl.add_column("Endpts", justify="right")
        tbl.add_column("Findings", justify="right")
        tbl.add_column("Duration", justify="right")

        for r in results:
            st = r["status"]
            if st == "success":
                status_str = "[green]done[/green]"
            elif st == "critical":
                status_str = "[red]CRITICAL[/red]"
            elif st == "high":
                status_str = "[yellow]HIGH[/yellow]"
            elif st == "failed":
                status_str = "[red]FAILED[/red]"
            else:
                status_str = f"[dim]{st}[/dim]"

            findings_str = str(r["findings"])
            if st == "critical":
                findings_str = f"[red]{r['findings']}[/red]"
            elif st == "high":
                findings_str = f"[yellow]{r['findings']}[/yellow]"

            tbl.add_row(
                r["target"],
                status_str,
                str(r["subdomains"]),
                str(r["alive"]),
                str(r["endpoints"]),
                findings_str,
                f"{r['duration']}s",
            )

        for t in in_progress:
            tbl.add_row(t, "[cyan]running...[/cyan]", "", "", "", "", "")

        return tbl

    # --- Main orchestrator ---
    async def _run_all() -> list[dict]:
        sem = asyncio.Semaphore(max(1, concurrency))
        results: list[dict] = []
        in_progress: set[str] = set()
        tasks: dict[str, asyncio.Task] = {}

        # For single target or sequential, just show inline output
        if len(targets) == 1 or concurrency <= 1:
            for t in targets:
                console.print(f"\n[bold]Target:[/bold] {t}")
                summary = await _run_single_target(t, sem)
                results.append(summary)
                _print_target_summary(summary)
            return results

        # Parallel execution with live table
        with Live(console=console, refresh_per_second=2) as live:
            for t in targets:
                in_progress.add(t)
                task = asyncio.create_task(_run_single_target(t, sem))
                tasks[t] = task

            # Wait for tasks as they complete
            for coro in asyncio.as_completed(tasks.values()):
                summary = await coro
                in_progress.discard(summary["target"])
                results.append(summary)
                live.update(_build_table(results, in_progress))

        return results

    # --- Run ---
    import time as _time

    total_start = _time.monotonic()
    results = asyncio.run(_run_all())
    total_duration = _time.monotonic() - total_start

    # --- Final summary ---
    if len(targets) > 1:
        console.print()

        # Aggregate stats
        total_subs = sum(r["subdomains"] for r in results)
        total_alive = sum(r["alive"] for r in results)
        total_findings = sum(r["findings"] for r in results)
        failed = sum(1 for r in results if r["status"] == "failed")
        critical = sum(1 for r in results if r["status"] == "critical")
        high = sum(1 for r in results if r["status"] == "high")

        summary_tbl = RichTable(title="Final Summary", border_style="green")
        summary_tbl.add_column("Metric", style="bold")
        summary_tbl.add_column("Value")
        summary_tbl.add_row("Targets", str(len(results)))
        summary_tbl.add_row("Completed", str(len(results) - failed))
        summary_tbl.add_row("Failed", f"[red]{failed}[/red]" if failed else "0")
        if critical:
            summary_tbl.add_row("Critical", f"[red]{critical}[/red]")
        if high:
            summary_tbl.add_row("High", f"[yellow]{high}[/yellow]")
        summary_tbl.add_row("Total Subdomains", str(total_subs))
        summary_tbl.add_row("Total Alive", str(total_alive))
        summary_tbl.add_row("Total Findings", str(total_findings))
        summary_tbl.add_row("Duration", f"{total_duration:.1f}s")
        console.print(summary_tbl)

    console.print("\n[bold green][+] Pipeline complete[/bold green]")


def _print_target_summary(summary: dict) -> None:
    """Print a compact summary for a single target."""
    st = summary["status"]
    if st == "critical":
        icon = "[red][!] CRITICAL[/red]"
    elif st == "high":
        icon = "[yellow][!] HIGH[/yellow]"
    elif st == "failed":
        icon = "[red][X] FAILED[/red]"
    else:
        icon = "[green][+][/green]"

    parts = [
        f"subs={summary['subdomains']}",
        f"alive={summary['alive']}",
        f"endpts={summary['endpoints']}",
        f"findings={summary['findings']}",
        f"{summary['duration']}s",
    ]
    console.print(f"  {icon} {summary['target']} -- {', '.join(parts)}")

    for err in summary.get("errors", []):
        console.print(f"    [yellow][~] {err}[/yellow]")


# ---------------------------------------------------------------------------
# Commands -- Recon subcommands
# ---------------------------------------------------------------------------


@recon_app.command("subfinder")
def recon_subfinder(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Target domain."),
) -> None:
    """Run subfinder for passive subdomain enumeration."""
    import asyncio

    cfg: BakiConfig = ctx.obj["config"]
    setup_logging(log_dir=cfg.output.dir, verbose=cfg.general.verbose)

    from modules.recon import run_subfinder
    from utils.helpers import create_run_dir

    console.print(f"[cyan]>>> subfinder[/cyan] >> {target}")

    async def _run() -> None:
        run_dir = create_run_dir(target, base_dir=cfg.output.dir)
        result = await run_subfinder(
            target,
            config_path=cfg.tools.subfinder,
            all_sources=cfg.recon.subfinder.all_sources,
            recursive=cfg.recon.subfinder.recursive,
            timeout=cfg.general.timeout,
        )
        result.save(run_dir, filename="recon_subfinder.json")
        count = result.item_count
        dur = result.duration
        console.print(f"  [green][+][/green] {count} subdomains ({dur:.1f}s)")
        if result.errors:
            for err in result.errors:
                console.print(f"  [yellow][~] {err}[/yellow]")

    asyncio.run(_run())


@recon_app.command("amass")
def recon_amass(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Target domain."),
    mode: str = typer.Option("enum", "--mode", "-m", help="enum | intel"),
) -> None:
    """Run amass for comprehensive subdomain enumeration."""
    import asyncio

    cfg: BakiConfig = ctx.obj["config"]
    setup_logging(log_dir=cfg.output.dir, verbose=cfg.general.verbose)

    from modules.recon import run_amass
    from utils.helpers import create_run_dir

    console.print(f"[cyan]>>> amass ({mode})[/cyan] >> {target}")

    async def _run() -> None:
        run_dir = create_run_dir(target, base_dir=cfg.output.dir)
        result = await run_amass(
            target,
            config_path=cfg.tools.amass,
            mode=mode,
            timeout=cfg.general.timeout,
        )
        result.save(run_dir, filename="recon_amass.json")
        count = result.item_count
        dur = result.duration
        console.print(f"  [green][+][/green] {count} subdomains ({dur:.1f}s)")
        if result.errors:
            for err in result.errors:
                console.print(f"  [yellow][~] {err}[/yellow]")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Commands -- Probe subcommands
# ---------------------------------------------------------------------------


@probe_app.command("httpx")
def probe_httpx(
    ctx: typer.Context,
    targets: str = typer.Argument(
        ..., help="Target host, URL, or file with hosts (one per line)."
    ),
) -> None:
    """Run httpx for HTTP probing and tech detection."""
    import asyncio

    cfg: BakiConfig = ctx.obj["config"]
    setup_logging(log_dir=cfg.output.dir, verbose=cfg.general.verbose)

    from modules.probing import run_httpx
    from utils.helpers import create_run_dir, parse_targets

    host_list = parse_targets(targets)
    console.print(f"[cyan]>>> httpx[/cyan] >> {len(host_list)} target(s)")

    async def _run() -> None:
        run_dir = create_run_dir(
            host_list[0] if len(host_list) == 1 else "multi",
            base_dir=cfg.output.dir,
        )
        httpx_cfg = cfg.probing.httpx
        result = await run_httpx(
            host_list,
            config_path=cfg.tools.httpx,
            status_code=httpx_cfg.status_code,
            tech_detect=httpx_cfg.tech_detect,
            content_length=httpx_cfg.content_length,
            title=httpx_cfg.title,
            favicon=httpx_cfg.favicon,
            response_time=httpx_cfg.response_time,
            follow_redirects=httpx_cfg.follow_redirects,
            threads=cfg.general.threads,
            timeout=cfg.general.timeout,
        )
        result.save(run_dir, filename="probing_httpx.json")
        console.print(
            f"  [green][+][/green] {result.item_count} alive ({result.duration:.1f}s)"
        )
        if result.errors:
            for err in result.errors:
                console.print(f"  [yellow][~] {err}[/yellow]")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Commands -- Discover subcommands
# ---------------------------------------------------------------------------


@discover_app.command("katana")
def discover_katana(
    ctx: typer.Context,
    targets: str = typer.Argument(
        ..., help="Target URL, or file with URLs (one per line)."
    ),
) -> None:
    """Run katana for content and endpoint discovery."""
    import asyncio

    cfg: BakiConfig = ctx.obj["config"]
    setup_logging(log_dir=cfg.output.dir, verbose=cfg.general.verbose)

    from modules.discovery import run_katana
    from utils.helpers import create_run_dir, parse_targets

    url_list = parse_targets(targets)
    console.print(f"[cyan]>>> katana[/cyan] >> {len(url_list)} target(s)")

    async def _run() -> None:
        run_dir = create_run_dir(
            url_list[0] if len(url_list) == 1 else "multi",
            base_dir=cfg.output.dir,
        )
        katana_cfg = cfg.discovery.katana
        result = await run_katana(
            url_list,
            config_path=cfg.tools.katana,
            depth=katana_cfg.depth,
            js_crawl=katana_cfg.js_crawl,
            field_scope=katana_cfg.field_scope,
            strategy=katana_cfg.strategy,
            threads=cfg.general.threads,
            timeout=cfg.general.timeout,
        )
        result.save(run_dir, filename="discovery_katana.json")
        count = result.item_count
        dur = result.duration
        console.print(f"  [green][+][/green] {count} endpoints ({dur:.1f}s)")
        if result.errors:
            for err in result.errors:
                console.print(f"  [yellow][~] {err}[/yellow]")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Commands -- Scan subcommands
# ---------------------------------------------------------------------------


@scan_app.command("nuclei")
def scan_nuclei(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Target URL or file of URLs."),
    severity: Optional[str] = typer.Option(
        None, "--severity", "-s", help="Comma-separated: critical,high,medium,low,info"
    ),
) -> None:
    """Run nuclei vulnerability scanner."""
    import asyncio

    cfg: BakiConfig = ctx.obj["config"]
    setup_logging(log_dir=cfg.output.dir, verbose=cfg.general.verbose)

    from modules.scanner import run_nuclei
    from utils.helpers import create_run_dir, parse_targets

    target_list = parse_targets(target)
    console.print(f"[cyan]>>> nuclei[/cyan] >> {len(target_list)} target(s)")

    async def _run() -> None:
        run_dir = create_run_dir(
            target_list[0] if len(target_list) == 1 else "multi",
            base_dir=cfg.output.dir,
        )
        nuclei_cfg = cfg.scanning.nuclei
        sev = (
            severity.split(",") if severity else [s.value for s in nuclei_cfg.severity]
        )

        custom_dir = nuclei_cfg.custom_templates_dir
        if custom_dir and not custom_dir.is_dir():
            custom_dir = None

        result = await run_nuclei(
            target_list,
            config_path=cfg.tools.nuclei,
            severity=sev,
            templates_dir=nuclei_cfg.templates_dir,
            custom_templates_dir=custom_dir,
            concurrency=nuclei_cfg.concurrency,
            rate_limit=nuclei_cfg.rate_limit,
            headless=nuclei_cfg.headless,
            timeout=cfg.general.timeout,
        )
        result.save(run_dir, filename="scan_nuclei.json")
        count = result.item_count
        dur = result.duration
        console.print(f"  [green][+][/green] {count} findings ({dur:.1f}s)")
        if result.errors:
            for err in result.errors:
                console.print(f"  [yellow][~] {err}[/yellow]")

    asyncio.run(_run())


@scan_app.command("ffuf")
def scan_ffuf(
    ctx: typer.Context,
    url: str = typer.Argument(..., help="Target URL with FUZZ keyword."),
    wordlist: Optional[Path] = typer.Option(
        None, "--wordlist", "-w", help="Wordlist path."
    ),
) -> None:
    """Run ffuf for content discovery."""
    import asyncio

    cfg: BakiConfig = ctx.obj["config"]
    setup_logging(log_dir=cfg.output.dir, verbose=cfg.general.verbose)

    from modules.scanner import run_ffuf
    from utils.helpers import create_run_dir

    console.print(f"[cyan]>>> ffuf[/cyan] >> {url}")

    async def _run() -> None:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        label = parsed.hostname or "unknown"
        run_dir = create_run_dir(label, base_dir=cfg.output.dir)

        ffuf_cfg = cfg.scanning.ffuf
        wl = wordlist or ffuf_cfg.wordlist

        result = await run_ffuf(
            url,
            config_path=cfg.tools.ffuf,
            wordlist=wl,
            extensions=ffuf_cfg.extensions,
            match_codes=ffuf_cfg.match_codes,
            threads=ffuf_cfg.threads,
            recursion_depth=ffuf_cfg.recursion_depth,
            timeout=cfg.general.timeout,
        )
        result.save(run_dir, filename="scan_ffuf.json")
        console.print(
            f"  [green][+][/green] {result.item_count} paths ({result.duration:.1f}s)"
        )
        if result.errors:
            for err in result.errors:
                console.print(f"  [yellow][~] {err}[/yellow]")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Commands -- Utility
# ---------------------------------------------------------------------------


@app.command(rich_help_panel="Utility")
def doctor(ctx: typer.Context) -> None:
    """Check tool availability and configuration health."""
    cfg: BakiConfig = ctx.obj.get("config", BakiConfig())
    setup_logging(log_dir=cfg.output.dir, verbose=cfg.general.verbose)

    console.print("\n[bold]Checking tool availability...[/bold]\n")

    resolved = resolve_all_tools(cfg.tools)

    table = Table(title="Tool Doctor", border_style="cyan")
    table.add_column("Tool", style="bold")
    table.add_column("Status")
    table.add_column("Path")

    for name, path in resolved.items():
        found = path is not None
        status = "[green][+][/green] found" if found else "[red][-] missing[/red]"
        table.add_row(name, status, path or "[dim]--[/dim]")

    console.print(table)

    # Config validation
    console.print("\n[bold]Config validation:[/bold] ", end="")
    try:
        BakiConfig.model_validate(cfg.model_dump())
        console.print("[green][+] valid[/green]")
    except Exception as exc:
        console.print(f"[red][-] {exc}[/red]")


@app.command(rich_help_panel="Utility")
def report(
    ctx: typer.Context,
    input_dir: Path = typer.Argument(
        Path("output/"), help="Run directory containing JSON results."
    ),
    fmt: str = typer.Option("all", "--format", "-f", help="markdown | html | all"),
) -> None:
    """Generate a report from collected JSON results."""
    cfg: BakiConfig = ctx.obj.get("config", BakiConfig())
    setup_logging(log_dir=cfg.output.dir, verbose=cfg.general.verbose)

    from utils.report import generate_report

    if not input_dir.is_dir():
        console.print(f"[red]Directory not found: {input_dir}[/red]")
        raise typer.Exit(1)

    formats = None if fmt == "all" else [fmt]
    console.print(f"[cyan]>>> report[/cyan] >> {input_dir}")

    generated = generate_report(input_dir, formats=formats)
    for f, path in generated.items():
        console.print(f"  [green][+][/green] {f}: {path}")

    if not generated:
        console.print("[yellow][~] No data found to generate report[/yellow]")


@app.command(rich_help_panel="Utility")
def notify(
    ctx: typer.Context,
    message: str = typer.Option("BakiBounty test notification", "--message", "-m"),
    service: str = typer.Option(
        "all", "--service", "-s", help="telegram | discord | all"
    ),
) -> None:
    """Test notification channels (Telegram/Discord)."""
    import asyncio

    cfg: BakiConfig = ctx.obj.get("config", BakiConfig())
    setup_logging(log_dir=cfg.output.dir, verbose=cfg.general.verbose)

    from utils.notify import send_discord, send_telegram

    if not cfg.notifications.enabled:
        console.print("[yellow][~] Notifications are disabled in config[/yellow]")
        raise typer.Exit(1)

    console.print(f"[cyan]>>> notify[/cyan] >> {service}")

    async def _run() -> None:
        tasks = []
        tg = cfg.notifications.telegram
        dc = cfg.notifications.discord

        if service in ("all", "telegram"):
            if tg.bot_token and tg.chat_id:
                console.print("  Sending to Telegram...")
                tasks.append(
                    ("telegram", send_telegram(message, tg.bot_token, tg.chat_id))
                )
            else:
                console.print("  [yellow][~] Telegram not configured[/yellow]")

        if service in ("all", "discord"):
            if dc.webhook_url:
                console.print("  Sending to Discord...")
                payload = {"content": message}
                tasks.append(("discord", send_discord(payload, dc.webhook_url)))
            else:
                console.print("  [yellow][~] Discord not configured[/yellow]")

        for name, coro in tasks:
            try:
                ok = await coro
                if ok:
                    console.print(f"  [green][+][/green] {name}: sent")
                else:
                    console.print(f"  [red][-] {name}: failed[/red]")
            except Exception as e:
                console.print(f"  [red][-] {name}: {e}[/red]")

    asyncio.run(_run())


@app.command(rich_help_panel="Utility")
def ai(
    ctx: typer.Context,
    input_dir: Path = typer.Argument(
        Path("output/"), help="Run directory containing scanner.json."
    ),
    provider: Optional[str] = typer.Option(
        None, "--provider", "-p", help="kilo | openai | anthropic"
    ),
    key: Optional[str] = typer.Option(
        None, "--key", "-k", help="API key (or set BAKIBOUNTY_AI_KEY env var)"
    ),
) -> None:
    """Analyze scan findings with AI."""
    import asyncio

    cfg: BakiConfig = ctx.obj.get("config", BakiConfig())
    setup_logging(log_dir=cfg.output.dir, verbose=cfg.general.verbose)

    from utils.ai import analyze_run, get_api_key, is_enabled

    # CLI overrides
    if provider:
        from config.schema import AiProvider

        cfg.ai.enabled = True
        cfg.ai.provider = AiProvider(provider)
    if key:
        cfg.ai.enabled = True
        cfg.ai.api_key = key

    if not cfg.ai.enabled:
        console.print(
            "[yellow][~] AI is disabled. Use --provider or enable in config[/yellow]"
        )
        raise typer.Exit(1)

    api_key = get_api_key(cfg)
    if not api_key:
        console.print("[red]No API key. Set BAKIBOUNTY_AI_KEY env var or --key[/red]")
        raise typer.Exit(1)

    if not input_dir.is_dir():
        console.print(f"[red]Directory not found: {input_dir}[/red]")
        raise typer.Exit(1)

    console.print(f"[cyan]>>> ai[/cyan] >> {input_dir}")
    console.print(f"  Provider: {cfg.ai.provider}, Model: {cfg.ai.model}")

    async def _run() -> None:
        result = await analyze_run(input_dir, cfg)
        if result:
            console.print(
                f"  [green][+][/green] Analyzed {result['analyzed']}/{result['findings']} findings"
            )
        else:
            console.print("  [yellow][~] No findings to analyze[/yellow]")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app()
