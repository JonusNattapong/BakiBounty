"""
BakiBounty - Scanner Module

Async wrappers for vulnerability scanning:
- nuclei: Template-based vulnerability scanner (ProjectDiscovery)
- ffuf: Fast web fuzzer for content discovery

Both produce structured findings for the reporting phase.
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


def _count_lines(path: Path) -> int:
    """Count non-empty lines in a file."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return sum(1 for line in fh if line.strip())
    except Exception:
        return 0


def _write_targets_file(targets: list[str], suffix: str = "_targets.txt") -> Path:
    """Write targets to a temp file for tool input."""
    import tempfile

    path = Path(tempfile.mktemp(suffix=suffix))
    with open(path, "w", encoding="utf-8") as fh:
        for t in targets:
            fh.write(t.strip() + "\n")
    return path


# ---------------------------------------------------------------------------
# Nuclei Runner
# ---------------------------------------------------------------------------


async def run_nuclei(
    targets: list[str] | Path,
    *,
    config_path: Optional[Path] = None,
    severity: Optional[list[str]] = None,
    templates_dir: Optional[Path] = None,
    custom_templates_dir: Optional[Path] = None,
    concurrency: int = 25,
    rate_limit: int = 150,
    headless: bool = False,
    timeout: int = 600,
    extra_args: Optional[Sequence[str]] = None,
) -> ModuleResult:
    """Run nuclei vulnerability scanner against targets.

    Args:
        targets: List of URLs/hosts OR Path to file.
        config_path: Explicit nuclei binary path.
        severity: Severity filter list (critical, high, medium, low, info).
        templates_dir: Custom templates directory (None = nuclei default).
        custom_templates_dir: Additional custom templates directory.
        concurrency: Number of concurrent template executions.
        rate_limit: Max requests per second.
        headless: Enable headless browser templates.
        timeout: Max execution time in seconds.
        extra_args: Additional CLI arguments.

    Returns:
        ModuleResult with vulnerability findings.
    """
    if severity is None:
        severity = ["critical", "high", "medium"]

    # Determine target source
    if isinstance(targets, Path):
        input_file = targets
        target_label = str(targets)
        target_count = _count_lines(targets)
    elif len(targets) > 20:
        input_file = _write_targets_file(targets, suffix="_nuclei_targets.txt")
        target_label = f"{len(targets)} targets"
        target_count = len(targets)
    else:
        input_file = None
        target_label = f"{len(targets)} targets"
        target_count = len(targets)

    logger.info("Starting nuclei on {} (severity: {})", target_label, severity)

    args: list[str] = [
        "-jsonl",  # JSON Lines output
        "-silent",  # Suppress banner/stats
        "-nc",  # No color
        "-c",
        str(concurrency),
        "-rl",
        str(rate_limit),
        "-severity",
        ",".join(severity),
        "-eid",
        "http-missing-security-headers",  # Exclude noisy info templates
    ]

    # Input source
    if input_file is not None:
        args.extend(["-l", str(input_file)])
    else:
        args.extend(["-u", targets[0] if isinstance(targets, list) else str(targets)])

    # Template directories
    if templates_dir is not None and templates_dir.is_dir():
        args.extend(["-t", str(templates_dir)])
    if custom_templates_dir is not None and custom_templates_dir.is_dir():
        args.extend(["-t", str(custom_templates_dir)])

    # Headless
    if headless:
        args.append("-headless")

    # Enable automatic template updates check (offline for speed)
    args.append("-nt")

    if extra_args:
        args.extend(extra_args)

    start = time.monotonic()
    result = await run_tool(
        "nuclei",
        args,
        config_path=config_path,
        timeout=timeout,
    )
    duration = time.monotonic() - start

    return _parse_nuclei_result(target_label, target_count, result, duration)


def _parse_nuclei_result(
    target_label: str,
    target_count: int,
    result: CommandResult,
    duration: float,
) -> ModuleResult:
    """Parse nuclei JSONL output into structured findings.

    Nuclei JSONL fields:
      {"template-id": "...", "info": {"name": "...", "severity": "...",
       "description": "...", "reference": [...], "tags": [...]},
       "host": "...", "matched-at": "...", "type": "...", "curl-command": "..."}
    """
    items: list[dict] = []
    errors: list[str] = []
    severity_counts: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    if result.timed_out:
        errors.append("nuclei timed out")
        return ModuleResult(
            module="scanner.nuclei",
            target=target_label,
            status="failed",
            items=[],
            errors=errors,
            duration=round(duration, 3),
        )

    if not result.success and not result.stdout.strip():
        if result.stderr:
            # Filter out common non-error noise
            stderr = result.stderr.strip()
            if "WRN" not in stderr and "INF" not in stderr:
                errors.append(f"nuclei: {stderr[:200]}")
        return ModuleResult(
            module="scanner.nuclei",
            target=target_label,
            status="failed",
            items=[],
            errors=errors,
            duration=round(duration, 3),
        )

    import orjson

    for line in result.stdout_lines:
        try:
            entry = orjson.loads(line)
        except orjson.JSONDecodeError:
            continue

        finding = _normalize_nuclei_entry(entry)
        if finding:
            items.append(finding)
            sev = finding.get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Deduplicate by template + host
    seen: set[tuple[str, str]] = set()
    unique_items: list[dict] = []
    for item in items:
        key = (item.get("template", ""), item.get("host", ""))
        if key not in seen:
            seen.add(key)
            unique_items.append(item)
    items = unique_items

    # Determine status
    critical = severity_counts.get("critical", 0)
    high = severity_counts.get("high", 0)
    status = "success"
    if critical > 0:
        status = "critical"
    elif high > 0:
        status = "high"

    logger.info(
        "nuclei found {} findings (C:{} H:{} M:{} L:{}) from {} targets in {:.1f}s",
        len(items),
        critical,
        high,
        severity_counts.get("medium", 0),
        severity_counts.get("low", 0),
        target_count,
        duration,
    )

    return ModuleResult(
        module="scanner.nuclei",
        target=target_label,
        status=status,
        items=items,
        errors=errors,
        duration=round(duration, 3),
    )


def _normalize_nuclei_entry(entry: dict) -> Optional[dict]:
    """Normalize a nuclei JSONL entry."""
    template_id = entry.get("template-id", "")
    if not template_id:
        return None

    info = entry.get("info", {})
    severity = info.get("severity", "info").lower()
    name = info.get("name", template_id)

    item: dict[str, Any] = {
        "template": template_id,
        "name": name,
        "severity": severity,
        "host": entry.get("host", ""),
        "matched_at": entry.get("matched-at", ""),
        "type": entry.get("type", ""),
    }

    # Description
    if "description" in info:
        item["description"] = info["description"]

    # References
    refs = info.get("reference", [])
    if refs:
        if isinstance(refs, list):
            item["references"] = refs
        else:
            item["references"] = [refs]

    # Tags
    tags = info.get("tags", [])
    if tags:
        if isinstance(tags, list):
            item["tags"] = tags
        else:
            item["tags"] = [t.strip() for t in str(tags).split(",")]

    # Classification (CVE, CWE, CVSS)
    classification = info.get("classification", {})
    if classification:
        if "cve-id" in classification:
            item["cve"] = classification["cve-id"]
        if "cwe-id" in classification:
            item["cwe"] = classification["cwe-id"]
        if "cvss-score" in classification:
            item["cvss"] = classification["cvss-score"]
        if "cvss-metrics" in classification:
            item["cvss_metrics"] = classification["cvss-metrics"]

    # Extracted results / evidence
    extracted = entry.get("extracted-results", [])
    if extracted:
        item["evidence"] = extracted

    # Matcher status
    if "matcher-status" in entry:
        item["matched"] = entry["matcher-status"]

    # Meta (template-level metadata)
    meta = info.get("metadata", {})
    if meta:
        item["metadata"] = meta

    return item


# ---------------------------------------------------------------------------
# ffuf Runner
# ---------------------------------------------------------------------------


async def run_ffuf(
    url: str,
    *,
    config_path: Optional[Path] = None,
    wordlist: Optional[Path] = None,
    extensions: Optional[list[str]] = None,
    match_codes: Optional[list[int]] = None,
    threads: int = 40,
    recursion_depth: int = 2,
    timeout: int = 600,
    extra_args: Optional[Sequence[str]] = None,
) -> ModuleResult:
    """Run ffuf for web content fuzzing.

    Args:
        url: Target URL with FUZZ keyword (e.g. https://example.com/FUZZ).
        config_path: Explicit ffuf binary path.
        wordlist: Path to wordlist file.
        extensions: File extensions to append.
        match_codes: HTTP status codes to match.
        threads: Concurrent fuzzing threads.
        recursion_depth: Recursion depth for discovered directories.
        timeout: Max execution time in seconds.
        extra_args: Additional CLI arguments.

    Returns:
        ModuleResult with discovered paths.
    """
    import tempfile

    # Defaults
    if wordlist is None:
        wordlist = Path("/usr/share/seclists/Discovery/Web-Content/common.txt")
    if extensions is None:
        extensions = [".php", ".asp", ".aspx", ".jsp", ".html"]
    if match_codes is None:
        match_codes = [200, 204, 301, 302, 307, 401, 403, 405, 500]

    target_label = url
    logger.info("Starting ffuf on {}", url)

    # JSON output file
    json_out = Path(tempfile.mktemp(suffix="_ffuf.json"))

    args: list[str] = [
        "-u",
        url,
        "-w",
        str(wordlist),
        "-t",
        str(threads),
        "-mc",
        ",".join(map(str, match_codes)),
        "-o",
        str(json_out),
        "-of",
        "json",
        "-noninteractive",
        "-s",  # Silent mode (suppress progress)
    ]

    # Extensions
    if extensions:
        args.extend(["-e", ",".join(extensions)])

    # Recursion
    if recursion_depth > 0:
        args.extend(["-recursion", "-recursion-depth", str(recursion_depth)])

    # Auto-calibrate (filter common noise)
    args.append("-ac")

    if extra_args:
        args.extend(extra_args)

    start = time.monotonic()
    result = await run_tool(
        "ffuf",
        args,
        config_path=config_path,
        timeout=timeout,
    )
    duration = time.monotonic() - start

    return _parse_ffuf_result(target_label, result, duration, json_out)


def _parse_ffuf_result(
    target_label: str,
    result: CommandResult,
    duration: float,
    json_file: Path,
) -> ModuleResult:
    """Parse ffuf JSON output into structured findings."""
    items: list[dict] = []
    errors: list[str] = []

    if result.timed_out:
        errors.append("ffuf timed out")
        return ModuleResult(
            module="scanner.ffuf",
            target=target_label,
            status="failed",
            items=[],
            errors=errors,
            duration=round(duration, 3),
        )

    # ffuf writes to JSON file, read from there
    if json_file.is_file():
        import orjson

        try:
            with open(json_file, "rb") as fh:
                data = orjson.loads(fh.read())

            results = data.get("results", [])
            for entry in results:
                item = _normalize_ffuf_entry(entry)
                if item:
                    items.append(item)

            # Clean up temp file
            json_file.unlink(missing_ok=True)

        except Exception as exc:
            errors.append(f"ffuf JSON parse error: {exc}")
    elif result.stderr:
        errors.append(f"ffuf: {result.stderr.strip()[:200]}")

    items = deduplicate_dicts(items, key="url")

    # Categorize by status
    by_status: dict[int, int] = {}
    for item in items:
        sc = item.get("status_code", 0)
        by_status[sc] = by_status.get(sc, 0) + 1

    status_str = "success" if items else "partial"
    if not items and not result.success:
        status_str = "failed"

    logger.info(
        "ffuf found {} paths from {} in {:.1f}s (status breakdown: {})",
        len(items),
        target_label,
        duration,
        ", ".join(f"{k}:{v}" for k, v in sorted(by_status.items())),
    )

    return ModuleResult(
        module="scanner.ffuf",
        target=target_label,
        status=status_str,
        items=items,
        errors=errors,
        duration=round(duration, 3),
    )


def _normalize_ffuf_entry(entry: dict) -> Optional[dict]:
    """Normalize a single ffuf result entry."""
    url = entry.get("url", "")
    if not url:
        return None

    item: dict[str, Any] = {"url": url}

    status = entry.get("status", 0)
    item["status_code"] = status

    # Size info
    if "length" in entry:
        item["content_length"] = entry["length"]
    if "content-type" in entry.get("result", {}):
        item["content_type"] = entry["result"]["content-type"]
    elif "content_type" in entry:
        item["content_type"] = entry["content_type"]

    # Words / lines
    if "words" in entry:
        item["words"] = entry["words"]
    if "lines" in entry:
        item["lines"] = entry["lines"]

    # Duration
    if "duration" in entry:
        item["response_time"] = entry["duration"]

    # Redirect location
    redirect = entry.get("redirectlocation", "")
    if redirect:
        item["redirect"] = redirect

    # Input values (the FUZZ word that matched)
    inp = entry.get("input", {})
    if inp:
        item["input"] = inp

    return item


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


async def run_scanner(
    target: str,
    config: Any,
    run_dir: Optional[Path] = None,
) -> ModuleResult:
    """Run vulnerability scanning on discovered endpoints.

    Runs nuclei on all URLs and optionally ffuf on discovered paths.

    Args:
        target: Root domain (for labeling).
        config: BakiConfig instance.
        run_dir: Output directory from previous phases.

    Returns:
        Merged ModuleResult with all findings.
    """
    import asyncio

    if run_dir is None:
        run_dir = create_run_dir(target, base_dir=config.output.dir)

    tasks: list[asyncio.Task] = []

    # --- nuclei ---
    nuclei_targets: list[str] | Path = []

    # Use alive URLs if available, else endpoints, else subdomains
    for candidate in ["alive_urls.txt", "endpoints.txt", "subdomains.txt"]:
        path = run_dir / candidate
        if path.is_file() and _count_lines(path) > 0:
            nuclei_targets = path
            logger.info("nuclei targets: {} (from {})", _count_lines(path), candidate)
            break

    if nuclei_targets:
        nuclei_cfg = config.scanning.nuclei
        sev_list = [s.value for s in nuclei_cfg.severity]

        # Check for custom templates dir
        custom_dir = nuclei_cfg.custom_templates_dir
        if custom_dir and not custom_dir.is_dir():
            custom_dir = None

        tasks.append(
            asyncio.create_task(
                run_nuclei(
                    nuclei_targets,
                    config_path=config.tools.nuclei,
                    severity=sev_list,
                    templates_dir=nuclei_cfg.templates_dir,
                    custom_templates_dir=custom_dir,
                    concurrency=nuclei_cfg.concurrency,
                    rate_limit=nuclei_cfg.rate_limit,
                    headless=nuclei_cfg.headless,
                    timeout=config.general.timeout,
                ),
                name="nuclei",
            )
        )
    else:
        logger.warning("No targets for nuclei scan")

    # --- ffuf (optional, only if we have alive URLs with a base) ---
    # ffuf requires a URL with FUZZ keyword - run on first alive URL as demo
    # In production, you'd want more sophisticated URL selection
    alive_file = run_dir / "alive_urls.txt"
    if alive_file.is_file():
        ffuf_cfg = config.scanning.ffuf
        # Pick a representative base URL for fuzzing
        with open(alive_file, "r", encoding="utf-8") as fh:
            first_url = fh.readline().strip()

        if first_url:
            from urllib.parse import urlparse

            parsed = urlparse(first_url)
            if parsed.scheme and parsed.hostname:
                base = f"{parsed.scheme}://{parsed.hostname}"
                if parsed.port and parsed.port not in (80, 443):
                    base += f":{parsed.port}"
                fuzz_url = f"{base}/FUZZ"

                tasks.append(
                    asyncio.create_task(
                        run_ffuf(
                            fuzz_url,
                            config_path=config.tools.ffuf,
                            wordlist=ffuf_cfg.wordlist,
                            extensions=ffuf_cfg.extensions,
                            match_codes=ffuf_cfg.match_codes,
                            threads=ffuf_cfg.threads,
                            recursion_depth=ffuf_cfg.recursion_depth,
                            timeout=config.general.timeout,
                        ),
                        name="ffuf",
                    )
                )

    if not tasks:
        logger.warning("No scan tasks to run for {}", target)
        return ModuleResult(
            module="scanner",
            target=target,
            status="partial",
            items=[],
            errors=["No scan targets available"],
        )

    # Run scanners in parallel
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Collect and save
    valid_results: list[ModuleResult] = []
    all_errors: list[str] = []

    for i, res in enumerate(results):
        task_name = (
            tasks[i].get_name() if hasattr(tasks[i], "get_name") else f"scanner_{i}"
        )
        if isinstance(res, Exception):
            err = f"{task_name}: {res}"
            logger.error("Scanner failed: {}", err)
            all_errors.append(err)
        elif isinstance(res, ModuleResult):
            res.save(run_dir, filename=f"scan_{task_name}.json")
            if res.errors:
                all_errors.extend(res.errors)
            valid_results.append(res)

    # Merge results
    if valid_results:
        all_items: list[dict] = []
        total_duration = 0.0
        for r in valid_results:
            all_items.extend(r.items)
            total_duration += r.duration

        # Determine overall severity
        max_severity = "info"
        for item in all_items:
            sev = item.get("severity", "info").lower()
            if sev == "critical":
                max_severity = "critical"
                break
            elif sev == "high" and max_severity != "critical":
                max_severity = "high"
            elif sev == "medium" and max_severity not in ("critical", "high"):
                max_severity = "medium"

        merged = ModuleResult(
            module="scanner",
            target=target,
            status=max_severity if max_severity in ("critical", "high") else "success",
            items=all_items,
            errors=all_errors,
            duration=round(total_duration, 3),
        )
    else:
        merged = ModuleResult(
            module="scanner",
            target=target,
            status="failed",
            items=[],
            errors=all_errors or ["All scanners failed"],
        )

    # Save merged
    merged.save(run_dir, filename="scanner.json")

    # Count findings by severity
    severity_summary: dict[str, int] = {}
    for item in merged.items:
        sev = item.get("severity", "info").lower()
        severity_summary[sev] = severity_summary.get(sev, 0) + 1

    logger.info(
        "Scan complete for {}: {} findings ({}) in {:.1f}s",
        target,
        len(merged.items),
        ", ".join(f"{k}:{v}" for k, v in sorted(severity_summary.items())),
        merged.duration,
    )

    return merged
