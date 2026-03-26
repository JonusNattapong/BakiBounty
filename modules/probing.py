"""
BakiBounty - Probing Module

Async httpx wrapper for HTTP probing and technology detection.
Takes subdomain list from recon, outputs alive hosts with metadata.

httpx features used:
  - Status codes, content length, titles
  - Technology detection (Wappalyzer-based)
  - Favicon hashing (mmh3)
  - Response time measurement
  - Follow redirects, TLS info
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Optional, Sequence

from loguru import logger

from utils.helpers import (
    CommandResult,
    ModuleResult,
    deduplicate_dicts,
    run_tool,
)

# ---------------------------------------------------------------------------
# httpx Runner
# ---------------------------------------------------------------------------


async def run_httpx(
    targets: list[str] | Path,
    *,
    config_path: Optional[Path] = None,
    status_code: bool = True,
    tech_detect: bool = True,
    content_length: bool = True,
    title: bool = True,
    favicon: bool = True,
    response_time: bool = True,
    follow_redirects: bool = True,
    threads: int = 50,
    timeout: int = 300,
    extra_args: Optional[Sequence[str]] = None,
) -> ModuleResult:
    """Run httpx for HTTP probing on a list of hosts.

    Args:
        targets: List of host strings OR Path to a file (one host per line).
        config_path: Explicit httpx binary path.
        status_code: Include HTTP status codes.
        tech_detect: Enable technology detection.
        content_length: Include response content length.
        title: Extract page titles.
        favicon: Hash favicons (mmh3).
        response_time: Measure response time.
        follow_redirects: Follow HTTP redirects.
        threads: Concurrent probing threads.
        timeout: Max execution time in seconds.
        extra_args: Additional CLI arguments.

    Returns:
        ModuleResult with alive hosts and their metadata.
    """
    # Determine target source
    if isinstance(targets, Path):
        input_file = targets
        target_label = str(targets)
        target_count = _count_lines(targets)
    elif len(targets) > 50:
        # Write to temp file for large target lists
        input_file = _write_targets_file(targets)
        target_label = f"{len(targets)} targets"
        target_count = len(targets)
    else:
        input_file = None
        target_label = f"{len(targets)} targets"
        target_count = len(targets)

    logger.info("Starting httpx probe on {}", target_label)

    args: list[str] = [
        "-json",  # JSON output (one object per line)
        "-silent",  # Suppress banner/stats
        "-threads",
        str(threads),
    ]

    # Input source
    if input_file is not None:
        args.extend(["-l", str(input_file)])
    else:
        assert isinstance(targets, list)
        args.extend(["-u", ",".join(targets)])

    # Probing options
    if status_code:
        args.append("-status-code")
    if tech_detect:
        args.append("-tech-detect")
    if content_length:
        args.append("-content-length")
    if title:
        args.append("-title")
    if favicon:
        args.append("-favicon")
    if response_time:
        args.append("-response-time")
    if follow_redirects:
        args.append("-follow-redirects")

    # TLS info (always useful)
    args.append("-tls-probe")

    if extra_args:
        args.extend(extra_args)

    start = time.monotonic()
    result = await run_tool(
        "httpx",
        args,
        config_path=config_path,
        timeout=timeout,
    )
    duration = time.monotonic() - start

    return _parse_httpx_result(target_label, target_count, result, duration)


def _write_targets_file(targets: list[str]) -> Path:
    """Write targets to a temp file for httpx -l input."""
    import tempfile

    path = Path(tempfile.mktemp(suffix="_httpx_targets.txt"))
    with open(path, "w", encoding="utf-8") as fh:
        for t in targets:
            fh.write(t.strip() + "\n")
    return path


def _count_lines(path: Path) -> int:
    """Count non-empty lines in a file."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return sum(1 for line in fh if line.strip())
    except Exception:
        return 0


def _parse_httpx_result(
    target_label: str,
    target_count: int,
    result: CommandResult,
    duration: float,
) -> ModuleResult:
    """Parse httpx JSON output into ModuleResult."""
    items: list[dict] = []
    errors: list[str] = []

    if result.timed_out:
        errors.append("httpx timed out")
        return ModuleResult(
            module="probing.httpx",
            target=target_label,
            status="failed",
            items=[],
            errors=errors,
            duration=round(duration, 3),
        )

    if not result.success and not result.stdout.strip():
        if result.stderr:
            errors.append(f"httpx: {result.stderr.strip()[:200]}")
        return ModuleResult(
            module="probing.httpx",
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
            item = _normalize_httpx_entry(entry)
            if item:
                items.append(item)
        except orjson.JSONDecodeError:
            # Fallback: plain URL output
            clean = line.strip()
            if clean and ("http" in clean or "." in clean):
                items.append({"url": clean, "input": clean})

    items = deduplicate_dicts(items, key="url")

    status = "success" if items else "partial"
    alive_pct = (len(items) / target_count * 100) if target_count > 0 else 0

    logger.info(
        "httpx probed {} targets, {} alive ({:.1f}%) in {:.1f}s",
        target_count,
        len(items),
        alive_pct,
        duration,
    )

    return ModuleResult(
        module="probing.httpx",
        target=target_label,
        status=status,
        items=items,
        errors=errors,
        duration=round(duration, 3),
    )


def _normalize_httpx_entry(entry: dict) -> Optional[dict]:
    """Normalize a single httpx JSON line into a clean dict.

    httpx JSON fields (varies by flags):
      url, input, status_code, content_length, title,
      tech, method, host, content-type, chain_status_codes,
      favicon, response_time, a, cname, etc.
    """
    url = entry.get("url", "").strip()
    if not url:
        return None

    item: dict[str, Any] = {"url": url}

    # Input (original host)
    if "input" in entry:
        item["input"] = entry["input"]

    # Host extraction
    host = entry.get("host", "")
    if not host and url:
        # Extract host from URL
        from urllib.parse import urlparse

        parsed = urlparse(url)
        host = parsed.hostname or ""
    item["host"] = host

    # Status
    if "status_code" in entry:
        item["status_code"] = entry["status_code"]

    # Content length
    if "content_length" in entry:
        item["content_length"] = entry["content_length"]

    # Title
    if "title" in entry:
        item["title"] = entry["title"]

    # Technology detection
    tech = entry.get("tech")
    if tech:
        if isinstance(tech, list):
            item["tech"] = tech
        elif isinstance(tech, str):
            item["tech"] = [t.strip() for t in tech.split(",") if t.strip()]

    # Method
    if "method" in entry:
        item["method"] = entry["method"]

    # Content type
    if "content_type" in entry:
        item["content_type"] = entry["content_type"]

    # Response time
    if "response_time" in entry:
        rt = entry["response_time"]
        # httpx formats: "123.45ms" or "1.23s"
        item["response_time"] = rt

    # Favicon hash
    if "favicon" in entry:
        item["favicon_hash"] = entry["favicon"]

    # TLS info
    if "tls_probe" in entry:
        item["tls"] = entry["tls_probe"]
    elif "tls" in entry:
        item["tls"] = entry["tls"]

    # CNAME
    if "cname" in entry:
        cname = entry["cname"]
        if isinstance(cname, list):
            item["cname"] = cname
        elif cname:
            item["cname"] = [cname]

    # IP
    if "a" in entry:
        a = entry["a"]
        if isinstance(a, list):
            item["ip"] = a
        elif a:
            item["ip"] = [a]

    # Web server
    if "webserver" in entry:
        item["webserver"] = entry["webserver"]

    return item


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


async def run_probing(
    target: str,
    config: Any,
    run_dir: Optional[Path] = None,
    subdomains_file: Optional[Path] = None,
) -> ModuleResult:
    """Run HTTP probing on discovered subdomains.

    Args:
        target: Root domain (for labeling).
        config: BakiConfig instance.
        run_dir: Output directory from recon phase.
        subdomains_file: Path to subdomains.txt (auto-detected from run_dir if None).

    Returns:
        ModuleResult with alive hosts and metadata.
    """
    # Find subdomains file
    if subdomains_file is None:
        if run_dir is not None:
            subdomains_file = run_dir / "subdomains.txt"
        else:
            subdomains_file = Path("output") / "subdomains.txt"

    if not subdomains_file.is_file():
        logger.error("Subdomains file not found: {}", subdomains_file)
        return ModuleResult(
            module="probing",
            target=target,
            status="failed",
            items=[],
            errors=[f"Subdomains file not found: {subdomains_file}"],
        )

    target_count = _count_lines(subdomains_file)
    if target_count == 0:
        logger.warning("No subdomains to probe for {}", target)
        return ModuleResult(
            module="probing",
            target=target,
            status="partial",
            items=[],
            errors=["No subdomains to probe"],
        )

    logger.info("Probing {} subdomains for {}", target_count, target)

    httpx_cfg = config.probing.httpx
    result = await run_httpx(
        subdomains_file,
        config_path=config.tools.httpx,
        status_code=httpx_cfg.status_code,
        tech_detect=httpx_cfg.tech_detect,
        content_length=httpx_cfg.content_length,
        title=httpx_cfg.title,
        favicon=httpx_cfg.favicon,
        response_time=httpx_cfg.response_time,
        follow_redirects=httpx_cfg.follow_redirects,
        threads=config.general.threads,
        timeout=config.general.timeout,
    )

    # Save results
    if run_dir:
        result.save(run_dir, filename="probing.json")

        # Save alive URLs for downstream tools
        alive_urls = [item["url"] for item in result.items if "url" in item]
        alive_file = run_dir / "alive_urls.txt"
        with open(alive_file, "w", encoding="utf-8") as fh:
            fh.write("\n".join(sorted(alive_urls)))
        logger.info("Saved {} alive URLs to {}", len(alive_urls), alive_file)

    return result
