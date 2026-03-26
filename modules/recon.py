"""
BakiBounty - Reconnaissance Module

Async wrappers for passive/active subdomain enumeration:
- subfinder: Fast passive enumeration (many sources)
- amass: Deep enumeration (OWASP)

Both return structured results via ModuleResult.
Can run in parallel for maximum coverage.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Optional, Sequence

from loguru import logger

from utils.helpers import (
    CommandResult,
    ModuleResult,
    create_run_dir,
    deduplicate_dicts,
    run_tool,
)

# ---------------------------------------------------------------------------
# Subfinder
# ---------------------------------------------------------------------------


async def run_subfinder(
    target: str,
    *,
    config_path: Optional[Path] = None,
    all_sources: bool = True,
    recursive: bool = True,
    timeout: int = 300,
    extra_args: Optional[Sequence[str]] = None,
) -> ModuleResult:
    """Run subfinder for passive subdomain enumeration.

    Args:
        target: Root domain to enumerate.
        config_path: Explicit subfinder binary path (or auto-resolve).
        all_sources: Use all available sources.
        recursive: Enable recursive subdomain discovery.
        timeout: Max execution time in seconds.
        extra_args: Additional CLI arguments.

    Returns:
        ModuleResult with discovered subdomains as items.
    """
    logger.info("Starting subfinder for: {}", target)

    args: list[str] = [
        "-d",
        target,
        "-silent",  # Only output subdomains, one per line
        "-json",  # JSON output for structured parsing
    ]

    if all_sources:
        args.append("-all")
    if recursive:
        args.append("-recursive")
    if extra_args:
        args.extend(extra_args)

    start = time.monotonic()
    result = await run_tool(
        "subfinder",
        args,
        config_path=config_path,
        timeout=timeout,
    )
    duration = time.monotonic() - start

    return _parse_subfinder_result(target, result, duration)


def _parse_subfinder_result(
    target: str,
    result: CommandResult,
    duration: float,
) -> ModuleResult:
    """Parse subfinder JSON output into ModuleResult."""
    items: list[dict] = []
    errors: list[str] = []

    if result.timed_out:
        errors.append("subfinder timed out")
        return ModuleResult(
            module="recon.subfinder",
            target=target,
            status="failed",
            items=[],
            errors=errors,
            duration=round(duration, 3),
        )

    if not result.success:
        if result.stderr:
            errors.append(f"subfinder: {result.stderr.strip()[:200]}")
        return ModuleResult(
            module="recon.subfinder",
            target=target,
            status="failed",
            items=[],
            errors=errors,
            duration=round(duration, 3),
        )

    # Parse JSON output (one JSON object per line)
    import orjson

    for line in result.stdout_lines:
        try:
            entry = orjson.loads(line)
            subdomain = entry.get("host", "").strip()
            if subdomain:
                item: dict = {"host": subdomain, "source": "subfinder"}
                # Capture additional fields if present
                if "ip" in entry:
                    item["ip"] = entry["ip"]
                if "source" in entry:
                    item["discovery_source"] = entry["source"]
                items.append(item)
        except orjson.JSONDecodeError:
            # Fallback: treat as plain subdomain line
            clean = line.strip()
            if clean and "." in clean:
                items.append({"host": clean, "source": "subfinder"})

    # Deduplicate
    items = deduplicate_dicts(items, key="host")

    status = "success" if items else "partial"
    if not items and result.returncode == 0:
        logger.warning("subfinder returned 0 results for {}", target)

    logger.info(
        "subfinder found {} subdomains for {} ({:.1f}s)",
        len(items),
        target,
        duration,
    )

    return ModuleResult(
        module="recon.subfinder",
        target=target,
        status=status,
        items=items,
        errors=errors,
        duration=round(duration, 3),
    )


# ---------------------------------------------------------------------------
# Amass
# ---------------------------------------------------------------------------


async def run_amass(
    target: str,
    *,
    config_path: Optional[Path] = None,
    mode: str = "enum",
    timeout: int = 600,
    extra_args: Optional[Sequence[str]] = None,
) -> ModuleResult:
    """Run amass for comprehensive subdomain enumeration.

    Args:
        target: Root domain to enumerate.
        config_path: Explicit amass binary path (or auto-resolve).
        mode: "enum" (enumeration) or "intel" (intelligence gathering).
        timeout: Max execution time (amass is slow, default 600s).
        extra_args: Additional CLI arguments.

    Returns:
        ModuleResult with discovered subdomains as items.
    """
    logger.info("Starting amass ({}) for: {}", mode, target)

    args: list[str] = []

    if mode == "intel":
        args = [
            "intel",
            "-d",
            target,
            "-whois",
        ]
    else:
        args = [
            "enum",
            "-d",
            target,
            "-passive",  # Passive only (faster, no active probing)
            "-norecursive",  # We handle recursion at pipeline level
        ]

    if extra_args:
        args.extend(extra_args)

    start = time.monotonic()
    result = await run_tool(
        "amass",
        args,
        config_path=config_path,
        timeout=timeout,
    )
    duration = time.monotonic() - start

    return _parse_amass_result(target, result, duration, mode)


def _parse_amass_result(
    target: str,
    result: CommandResult,
    duration: float,
    mode: str,
) -> ModuleResult:
    """Parse amass output into ModuleResult.

    Amass enum -passive outputs one subdomain per line (plain text).
    Amass intel outputs FQDNs one per line.
    """
    items: list[dict] = []
    errors: list[str] = []

    if result.timed_out:
        errors.append("amass timed out")
        return ModuleResult(
            module="recon.amass",
            target=target,
            status="failed",
            items=[],
            errors=errors,
            duration=round(duration, 3),
        )

    if not result.success and not result.stdout.strip():
        if result.stderr:
            errors.append(f"amass: {result.stderr.strip()[:200]}")
        return ModuleResult(
            module="recon.amass",
            target=target,
            status="failed",
            items=[],
            errors=errors,
            duration=round(duration, 3),
        )

    # Parse plain text output (one subdomain per line)
    for line in result.stdout_lines:
        subdomain = line.strip().lower()
        if subdomain and "." in subdomain:
            items.append({"host": subdomain, "source": "amass"})

    items = deduplicate_dicts(items, key="host")

    status = "success" if items else "partial"
    logger.info(
        "amass ({}) found {} subdomains for {} ({:.1f}s)",
        mode,
        len(items),
        target,
        duration,
    )

    return ModuleResult(
        module="recon.amass",
        target=target,
        status=status,
        items=items,
        errors=errors,
        duration=round(duration, 3),
    )


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


async def run_recon(
    target: str,
    config: Any,
    run_dir: Optional[Path] = None,
) -> ModuleResult:
    """Run all configured recon sources in parallel and merge results.

    Args:
        target: Root domain to enumerate.
        config: BakiConfig instance.
        run_dir: Output directory for this run (auto-created if None).

    Returns:
        Merged ModuleResult with all discovered subdomains.
    """
    import asyncio


    if run_dir is None:
        run_dir = create_run_dir(target, base_dir=config.output.dir)

    sources = config.recon.sources
    logger.info("Recon sources for {}: {}", target, sources)

    tasks: list[asyncio.Task] = []

    if "subfinder" in sources:
        tasks.append(
            asyncio.create_task(
                run_subfinder(
                    target,
                    config_path=config.tools.subfinder,
                    all_sources=config.recon.subfinder.all_sources,
                    recursive=config.recon.subfinder.recursive,
                    timeout=config.general.timeout,
                ),
                name="subfinder",
            )
        )

    if "amass" in sources:
        tasks.append(
            asyncio.create_task(
                run_amass(
                    target,
                    config_path=config.tools.amass,
                    mode=config.recon.amass.mode.value,
                    timeout=config.general.timeout,
                ),
                name="amass",
            )
        )

    if not tasks:
        logger.warning("No recon sources configured for {}", target)
        return ModuleResult(
            module="recon",
            target=target,
            status="partial",
            items=[],
            errors=["No recon sources configured"],
        )

    # Run all sources in parallel
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Collect successful results, log failures
    valid_results: list[ModuleResult] = []
    all_errors: list[str] = []

    for i, res in enumerate(results):
        task_name = (
            tasks[i].get_name() if hasattr(tasks[i], "get_name") else f"source_{i}"
        )
        if isinstance(res, Exception):
            err = f"{task_name}: {res}"
            logger.error("Recon source failed: {}", err)
            all_errors.append(err)
        elif isinstance(res, ModuleResult):
            # Save individual source result
            res.save(run_dir, filename=f"recon_{task_name}.json")
            if res.errors:
                all_errors.extend(res.errors)
            valid_results.append(res)

    # Merge all valid results
    if valid_results:
        all_items: list[dict] = []
        total_duration = 0.0
        for r in valid_results:
            all_items.extend(r.items)
            total_duration += r.duration

        # Global dedup
        all_items = deduplicate_dicts(all_items, key="host")

        merged = ModuleResult(
            module="recon",
            target=target,
            status="success" if not all_errors else "partial",
            items=all_items,
            errors=all_errors,
            duration=round(total_duration, 3),
        )
    else:
        merged = ModuleResult(
            module="recon",
            target=target,
            status="failed",
            items=[],
            errors=all_errors or ["All recon sources failed"],
        )

    # Save merged result
    merged.save(run_dir, filename="recon.json")

    # Also save flat subdomain list for downstream tools
    subdomains = [item["host"] for item in merged.items if "host" in item]
    subdomains_file = run_dir / "subdomains.txt"
    with open(subdomains_file, "w", encoding="utf-8") as fh:
        fh.write("\n".join(sorted(subdomains)))
    logger.info("Saved {} subdomains to {}", len(subdomains), subdomains_file)

    logger.info(
        "Recon complete for {}: {} unique subdomains ({:.1f}s)",
        target,
        len(merged.items),
        merged.duration,
    )

    return merged
