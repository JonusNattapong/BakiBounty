"""
BakiBounty - Discovery Module

Async katana wrapper for content and endpoint discovery.
Takes alive URLs from probing, crawls for:
  - Endpoints and routes
  - JavaScript files and API endpoints
  - Parameters and form fields
  - Hidden paths and directories

Katana features used:
  - Headless crawling (optional)
  - JS file parsing
  - Scope control (rdn = registered domain name)
  - Configurable depth and strategy
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Optional, Sequence

from loguru import logger

from utils.helpers import (
    CommandResult,
    ModuleResult,
    run_tool,
)

# ---------------------------------------------------------------------------
# Katana Runner
# ---------------------------------------------------------------------------


async def run_katana(
    targets: list[str] | Path,
    *,
    config_path: Optional[Path] = None,
    depth: int = 3,
    js_crawl: bool = True,
    field_scope: str = "rdn",
    strategy: str = "breadth-first",
    threads: int = 10,
    timeout: int = 600,
    extra_args: Optional[Sequence[str]] = None,
) -> ModuleResult:
    """Run katana for web content and endpoint discovery.

    Args:
        targets: List of URL strings OR Path to a file (one URL per line).
        config_path: Explicit katana binary path.
        depth: Crawling depth (1-10).
        js_crawl: Parse JavaScript files for endpoints.
        field_scope: Scope control (rdn = same registered domain).
        strategy: Crawling strategy (breadth-first | depth-first).
        threads: Concurrent crawling threads.
        timeout: Max execution time in seconds.
        extra_args: Additional CLI arguments.

    Returns:
        ModuleResult with discovered endpoints and metadata.
    """
    # Determine target source
    if isinstance(targets, Path):
        input_file = targets
        target_label = str(targets)
        target_count = _count_lines(targets)
    elif len(targets) > 20:
        input_file = _write_targets_file(targets)
        target_label = f"{len(targets)} targets"
        target_count = len(targets)
    else:
        input_file = None
        target_label = f"{len(targets)} targets"
        target_count = len(targets)

    logger.info("Starting katana on {}", target_label)

    args: list[str] = [
        "-silent",  # Suppress banner
        "-jsonl",  # JSON Lines output
        "-d",
        str(depth),
        "-fs",
        field_scope,
        "-strategy",
        strategy,
        "-c",
        str(threads),
        "-jc",  # JavaScript parsing (always useful)
        "-kf",
        "url,path,param",  # Known files: url, path, param
    ]

    # Input source
    if input_file is not None:
        args.extend(["-list", str(input_file)])
    else:
        args.extend(["-u", targets[0] if isinstance(targets, list) else str(targets)])

    # Headless mode (optional, slower but catches JS-rendered content)
    # Not enabled by default -- add via extra_args if needed

    if extra_args:
        args.extend(extra_args)

    start = time.monotonic()
    result = await run_tool(
        "katana",
        args,
        config_path=config_path,
        timeout=timeout,
    )
    duration = time.monotonic() - start

    return _parse_katana_result(target_label, target_count, result, duration)


def _write_targets_file(targets: list[str]) -> Path:
    """Write targets to a temp file for katana -list input."""
    import tempfile

    path = Path(tempfile.mktemp(suffix="_katana_targets.txt"))
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


def _parse_katana_result(
    target_label: str,
    target_count: int,
    result: CommandResult,
    duration: float,
) -> ModuleResult:
    """Parse katana JSONL output into structured items.

    Katana JSONL fields per line:
      {"endpoint": "url", "method": "GET", "source": "source_url",
       "tag": "input|a|script", "attribute_name": "href|src",
       "attribute_value": "/path", "type": "js|endpoint"}
    """
    items: list[dict] = []
    errors: list[str] = []
    seen_urls: set[str] = set()

    if result.timed_out:
        errors.append("katana timed out")
        return ModuleResult(
            module="discovery.katana",
            target=target_label,
            status="failed",
            items=[],
            errors=errors,
            duration=round(duration, 3),
        )

    if not result.success and not result.stdout.strip():
        if result.stderr:
            errors.append(f"katana: {result.stderr.strip()[:200]}")
        return ModuleResult(
            module="discovery.katana",
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
            # Fallback: plain URL output
            clean = line.strip()
            if clean and ("http" in clean or "/" in clean):
                url = clean
                if url not in seen_urls:
                    seen_urls.add(url)
                    items.append({"url": url, "source": "katana"})
            continue

        item = _normalize_katana_entry(entry)
        if item:
            url = item.get("url", "")
            if url and url not in seen_urls:
                seen_urls.add(url)
                items.append(item)

    status = "success" if items else "partial"

    # Categorize results
    endpoints = [i for i in items if i.get("type") == "endpoint"]
    js_files = [i for i in items if i.get("type") == "js"]
    params = [i for i in items if i.get("parameter")]
    unique_paths = {i.get("path") for i in items if i.get("path")}

    logger.info(
        "katana found {} items ({} endpoints, {} JS, {} params, {} paths) "
        "from {} targets in {:.1f}s",
        len(items),
        len(endpoints),
        len(js_files),
        len(params),
        len(unique_paths),
        target_count,
        duration,
    )

    return ModuleResult(
        module="discovery.katana",
        target=target_label,
        status=status,
        items=items,
        errors=errors,
        duration=round(duration, 3),
    )


def _normalize_katana_entry(entry: dict) -> Optional[dict]:
    """Normalize a katana JSONL entry.

    Katana output format varies by version. Handle both v1 and common formats.
    """
    # v2+ format: {"endpoint": "...", "method": "...", ...}
    url = entry.get("endpoint") or entry.get("url") or ""
    url = url.strip()
    if not url:
        return None

    item: dict[str, Any] = {"url": url}

    # Source URL (where this was found)
    if "source" in entry:
        item["source_url"] = entry["source"]

    # HTTP method
    if "method" in entry:
        item["method"] = entry["method"]
    else:
        item["method"] = "GET"

    # Tag context (a, script, form, input, etc.)
    if "tag" in entry:
        item["tag"] = entry["tag"]

    # Attribute info (href, src, action, etc.)
    if "attribute_name" in entry:
        item["attribute"] = entry["attribute_name"]
    if "attribute_value" in entry:
        item["attribute_value"] = entry["attribute_value"]

    # Type classification
    entry_type = entry.get("type", "")
    if entry_type:
        item["type"] = entry_type
    elif url.endswith(".js"):
        item["type"] = "js"
    else:
        item["type"] = "endpoint"

    # Extract path from URL
    from urllib.parse import parse_qs, urlparse

    try:
        parsed = urlparse(url)
        item["path"] = parsed.path or "/"
        item["host"] = parsed.hostname or ""

        # Parameters
        params = parse_qs(parsed.query)
        if params:
            item["parameter"] = list(params.keys())
            item["param_count"] = len(params)
    except Exception:
        pass

    # Response code if available
    if "status_code" in entry:
        item["status_code"] = entry["status_code"]

    return item


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


async def run_discovery(
    target: str,
    config: Any,
    run_dir: Optional[Path] = None,
    alive_file: Optional[Path] = None,
) -> ModuleResult:
    """Run content discovery on alive URLs.

    Args:
        target: Root domain (for labeling).
        config: BakiConfig instance.
        run_dir: Output directory from probing phase.
        alive_file: Path to alive_urls.txt (auto-detected from run_dir if None).

    Returns:
        ModuleResult with discovered endpoints and metadata.
    """
    # Find alive URLs file
    if alive_file is None:
        if run_dir is not None:
            alive_file = run_dir / "alive_urls.txt"
        else:
            alive_file = Path("output") / "alive_urls.txt"

    if not alive_file.is_file():
        logger.error("Alive URLs file not found: {}", alive_file)
        return ModuleResult(
            module="discovery",
            target=target,
            status="failed",
            items=[],
            errors=[f"Alive URLs file not found: {alive_file}"],
        )

    target_count = _count_lines(alive_file)
    if target_count == 0:
        logger.warning("No alive URLs to crawl for {}", target)
        return ModuleResult(
            module="discovery",
            target=target,
            status="partial",
            items=[],
            errors=["No alive URLs to crawl"],
        )

    logger.info("Crawling {} alive URLs for {}", target_count, target)

    katana_cfg = config.discovery.katana
    result = await run_katana(
        alive_file,
        config_path=config.tools.katana,
        depth=katana_cfg.depth,
        js_crawl=katana_cfg.js_crawl,
        field_scope=katana_cfg.field_scope,
        strategy=katana_cfg.strategy,
        threads=config.general.threads,
        timeout=config.general.timeout,
    )

    # Save results
    if run_dir:
        result.save(run_dir, filename="discovery.json")

        # Save discovered endpoints for downstream tools
        endpoints = [
            item["url"]
            for item in result.items
            if "url" in item and item.get("type") != "js"
        ]
        js_files = [item["url"] for item in result.items if item.get("type") == "js"]

        if endpoints:
            ep_file = run_dir / "endpoints.txt"
            with open(ep_file, "w", encoding="utf-8") as fh:
                fh.write("\n".join(sorted(set(endpoints))))
            logger.info("Saved {} endpoints to {}", len(endpoints), ep_file)

        if js_files:
            js_file = run_dir / "js_files.txt"
            with open(js_file, "w", encoding="utf-8") as fh:
                fh.write("\n".join(sorted(set(js_files))))
            logger.info("Saved {} JS files to {}", len(js_files), js_file)

    return result
