"""
BakiBounty - Utility Helpers

Core infrastructure used by all modules:
- Tool resolution (find binaries in PATH or config)
- Async subprocess execution with timeout/capture
- JSON I/O (orjson-backed, fast)
- Output directory management
- Target parsing (domain string or file input)
- Result deduplication
"""

from __future__ import annotations

import asyncio
import shutil
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Sequence

import orjson
from loguru import logger

# ---------------------------------------------------------------------------
# Tool Resolution
# ---------------------------------------------------------------------------

# Maps tool names to their common binary names (fallback if config path is None)
_TOOL_ALIASES: dict[str, str] = {
    "subfinder": "subfinder",
    "amass": "amass",
    "httpx": "httpx",
    "nuclei": "nuclei",
    "katana": "katana",
    "ffuf": "ffuf",
    "naabu": "naabu",
}

_tool_cache: dict[str, Optional[str]] = {}


def resolve_tool(name: str, config_path: Optional[Path] = None) -> Optional[str]:
    """Resolve a tool binary path.

    Priority:
      1. Explicit config path (if provided and exists)
      2. Cached lookup
      3. shutil.which() on PATH

    Returns absolute path string or None if not found.
    """
    # 1. Config override
    if config_path is not None:
        resolved = str(config_path)
        if Path(resolved).exists():
            _tool_cache[name] = resolved
            return resolved
        logger.warning("Config path for {} does not exist: {}", name, resolved)
        return None

    # 2. Cache hit
    if name in _tool_cache:
        return _tool_cache[name]

    # 3. PATH lookup
    binary = _TOOL_ALIASES.get(name, name)
    found = shutil.which(binary)
    _tool_cache[name] = found

    if found:
        logger.debug("Resolved {} -> {}", name, found)
    else:
        logger.debug("Tool not found: {}", name)

    return found


def resolve_all_tools(tools_config: Any) -> dict[str, Optional[str]]:
    """Resolve all tools from a ToolsConfig model. Returns {name: path|None}."""
    results: dict[str, Optional[str]] = {}
    for name in _TOOL_ALIASES:
        config_path = getattr(tools_config, name, None)
        results[name] = resolve_tool(name, config_path)
    return results


# ---------------------------------------------------------------------------
# Async Subprocess Runner
# ---------------------------------------------------------------------------


@dataclass
class CommandResult:
    """Structured result from subprocess execution."""

    cmd: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration: float  # seconds
    timed_out: bool = False

    @property
    def success(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def stdout_lines(self) -> list[str]:
        return [line for line in self.stdout.splitlines() if line.strip()]

    @property
    def stderr_lines(self) -> list[str]:
        return [line for line in self.stderr.splitlines() if line.strip()]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


async def run_cmd(
    cmd: Sequence[str],
    *,
    timeout: int = 300,
    cwd: Optional[str | Path] = None,
    env: Optional[dict[str, str]] = None,
    stdin_data: Optional[str] = None,
    capture_stdout: bool = True,
    capture_stderr: bool = True,
) -> CommandResult:
    """Run an async subprocess with timeout and output capture.

    Args:
        cmd: Command and arguments as a sequence of strings.
        timeout: Max execution time in seconds.
        cwd: Working directory for the subprocess.
        env: Additional environment variables (merged with os.environ).
        stdin_data: Optional string to pipe to stdin.
        capture_stdout: Whether to capture stdout.
        capture_stderr: Whether to capture stderr.

    Returns:
        CommandResult with stdout, stderr, returncode, duration, timed_out.
    """
    import os

    merged_env = {**os.environ}
    if env:
        merged_env.update(env)

    start = time.monotonic()
    timed_out = False
    proc: Optional[asyncio.subprocess.Process] = None

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE if capture_stdout else None,
            stderr=asyncio.subprocess.PIPE if capture_stderr else None,
            stdin=asyncio.subprocess.PIPE if stdin_data else None,
            cwd=str(cwd) if cwd else None,
            env=merged_env,
        )

        stdin_bytes = stdin_data.encode() if stdin_data else None
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(input=stdin_bytes),
            timeout=timeout,
        )
        returncode = proc.returncode if proc.returncode is not None else -1

    except asyncio.TimeoutError:
        timed_out = True
        returncode = -1
        stdout_bytes = b""
        stderr_bytes = b""
        if proc is not None:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
        logger.warning("Command timed out after {}s: {}", timeout, " ".join(cmd))

    except FileNotFoundError:
        returncode = -1
        stdout_bytes = b""
        stderr_bytes = f"Command not found: {cmd[0]}".encode()
        logger.error("Binary not found: {}", cmd[0])

    except Exception as exc:
        returncode = -1
        stdout_bytes = b""
        stderr_bytes = str(exc).encode()
        logger.error("Subprocess error: {}", exc)

    duration = time.monotonic() - start

    return CommandResult(
        cmd=list(cmd),
        returncode=returncode,
        stdout=stdout_bytes.decode(errors="replace"),
        stderr=stderr_bytes.decode(errors="replace"),
        duration=round(duration, 3),
        timed_out=timed_out,
    )


async def run_tool(
    tool_name: str,
    args: Sequence[str],
    *,
    config_path: Optional[Path] = None,
    timeout: int = 300,
    cwd: Optional[str | Path] = None,
    **kwargs: Any,
) -> CommandResult:
    """Resolve a tool and run it. Returns CommandResult or raises if tool missing."""
    binary = resolve_tool(tool_name, config_path)
    if binary is None:
        return CommandResult(
            cmd=[tool_name, *args],
            returncode=-1,
            stdout="",
            stderr=f"Tool not found: {tool_name}. Install it or set path in config.",
            duration=0.0,
        )
    cmd = [binary, *map(str, args)]
    return await run_cmd(cmd, timeout=timeout, cwd=cwd, **kwargs)


# ---------------------------------------------------------------------------
# JSON I/O
# ---------------------------------------------------------------------------


def save_json(
    data: Any,
    path: str | Path,
    *,
    pretty: bool = True,
    mkdir: bool = True,
) -> Path:
    """Save data as JSON using orjson (fast).

    Args:
        data: Serializable data (dict, list, dataclass, etc.).
        path: Output file path.
        pretty: Pretty-print with indentation.
        mkdir: Create parent directories if missing.

    Returns:
        Resolved Path to the written file.
    """
    path = Path(path)
    if mkdir:
        path.parent.mkdir(parents=True, exist_ok=True)

    opts = orjson.OPT_INDENT_2 if pretty else 0
    # orjson handles dataclasses, datetime, etc. natively
    raw = orjson.dumps(
        data, option=opts | orjson.OPT_NON_STR_KEYS | orjson.OPT_SERIALIZE_NUMPY
    )

    with open(path, "wb") as fh:
        fh.write(raw)

    logger.debug("Saved JSON: {} ({} bytes)", path, len(raw))
    return path


def load_json(path: str | Path) -> Any:
    """Load JSON file using orjson.

    Raises:
        FileNotFoundError: If file doesn't exist.
        orjson.JSONDecodeError: If file is not valid JSON.
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"JSON file not found: {path}")

    with open(path, "rb") as fh:
        data = orjson.loads(fh.read())

    return data


def append_json_lines(items: list[dict], path: str | Path) -> Path:
    """Append items as newline-delimited JSON (JSONL) for streaming results.

    Each item is written as one JSON line. Good for large result sets.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "ab") as fh:
        for item in items:
            fh.write(orjson.dumps(item))
            fh.write(b"\n")

    return path


def load_json_lines(path: str | Path) -> list[dict]:
    """Load newline-delimited JSON (JSONL) file."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"JSONL file not found: {path}")

    items: list[dict] = []
    with open(path, "rb") as fh:
        for line in fh:
            line = line.strip()
            if line:
                items.append(orjson.loads(line))
    return items


# ---------------------------------------------------------------------------
# Output Directory Management
# ---------------------------------------------------------------------------


def create_run_dir(
    target: str,
    base_dir: str | Path = "output/",
) -> Path:
    """Create a timestamped output directory for a scan run.

    Structure: output/<target>_<YYYYMMDD_HHMMSS>/

    Returns:
        Path to the created directory.
    """
    base = Path(base_dir)
    # Sanitize target for filesystem
    safe_target = target.replace("://", "_").replace("/", "_").replace(":", "_")
    # Strip trailing separators
    safe_target = safe_target.rstrip("_/\\")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    run_dir = base / f"{safe_target}_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Created run directory: {}", run_dir)
    return run_dir


def find_latest_run_dir(
    target: str,
    base_dir: str | Path = "output/",
) -> Optional[Path]:
    """Find the most recent run directory for a given target.

    Returns:
        Path to latest run dir or None if no runs found.
    """
    base = Path(base_dir)
    if not base.is_dir():
        return None

    safe_target = target.replace("://", "_").replace("/", "_").replace(":", "_")
    safe_target = safe_target.rstrip("_/\\")

    candidates = sorted(
        base.glob(f"{safe_target}_*"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    return candidates[0] if candidates else None


# ---------------------------------------------------------------------------
# Target Parsing
# ---------------------------------------------------------------------------


def parse_targets(target_input: str) -> list[str]:
    """Parse target input into a list of domains/URLs.

    Accepts:
      - Single domain: "example.com"
      - URL: "https://example.com"
      - File path: "targets.txt" (one target per line)

    Returns:
        Deduplicated list of targets.
    """
    path = Path(target_input)

    if path.is_file():
        logger.info("Loading targets from file: {}", path)
        with open(path, "r", encoding="utf-8") as fh:
            lines = [line.strip() for line in fh.readlines()]
    else:
        lines = [target_input.strip()]

    # Clean and deduplicate
    targets: list[str] = []
    seen: set[str] = set()
    for line in lines:
        if not line or line.startswith("#"):
            continue
        # Strip protocol and trailing slashes for normalization
        clean = line.strip().rstrip("/")
        if clean not in seen:
            seen.add(clean)
            targets.append(clean)

    logger.info("Parsed {} target(s)", len(targets))
    return targets


# ---------------------------------------------------------------------------
# Result Aggregation
# ---------------------------------------------------------------------------


@dataclass
class ModuleResult:
    """Standardized result container for any pipeline module."""

    module: str  # e.g. "recon", "probing"
    target: str  # Target domain
    status: str = "success"  # success | failed | partial
    items: list[dict] = field(default_factory=list)
    item_count: int = 0
    errors: list[str] = field(default_factory=list)
    duration: float = 0.0
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def __post_init__(self) -> None:
        if self.item_count == 0:
            self.item_count = len(self.items)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["item_count"] = self.item_count
        return d

    def save(self, run_dir: str | Path, filename: Optional[str] = None) -> Path:
        """Save this result to a JSON file in the run directory."""
        name = filename or f"{self.module}.json"
        path = Path(run_dir) / name
        return save_json(self.to_dict(), path)


def deduplicate_dicts(
    items: list[dict],
    key: str = "host",
) -> list[dict]:
    """Deduplicate a list of dicts by a key field."""
    seen: set[Any] = set()
    unique: list[dict] = []
    for item in items:
        val = item.get(key)
        if val is not None and val not in seen:
            seen.add(val)
            unique.append(item)
    return unique


def merge_module_results(*results: ModuleResult) -> ModuleResult:
    """Merge multiple ModuleResults into one (same target, same module)."""
    if not results:
        raise ValueError("No results to merge")

    first = results[0]
    all_items: list[dict] = []
    all_errors: list[str] = []
    total_duration = 0.0

    for r in results:
        all_items.extend(r.items)
        all_errors.extend(r.errors)
        total_duration += r.duration

    return ModuleResult(
        module=first.module,
        target=first.target,
        status="success" if not all_errors else "partial",
        items=all_items,
        item_count=len(all_items),
        errors=all_errors,
        duration=round(total_duration, 3),
    )
