"""
BakiBounty - Logging Utilities

Dual logging setup:
- loguru for file-based structured logs (JSON)
- rich for beautiful console output
"""

from __future__ import annotations

import sys
from pathlib import Path

from loguru import logger
from rich.console import Console
from rich.theme import Theme

# ---------------------------------------------------------------------------
# Rich console (singleton)
# ---------------------------------------------------------------------------

custom_theme = Theme(
    {
        "info": "cyan",
        "warning": "yellow",
        "danger": "bold red",
        "success": "bold green",
        "highlight": "bold magenta",
        "dim": "dim",
    }
)

console = Console(theme=custom_theme)


# ---------------------------------------------------------------------------
# Loguru setup
# ---------------------------------------------------------------------------


def setup_logging(
    log_dir: Path | str = "output/",
    level: str = "INFO",
    verbose: bool = False,
) -> None:
    """Configure loguru with file + stderr sinks."""
    logger.remove()  # remove default handler

    # Console sink (compact)
    logger.add(
        sys.stderr,
        level="DEBUG" if verbose else "INFO",
        format="<level>{level: <8}</level> | {message}",
        colorize=True,
        backtrace=False,
        diagnose=False,
    )

    # File sink (structured JSON)
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)
    logger.add(
        log_path / "bakibounty.log",
        level="DEBUG",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} | {message}",
        rotation="10 MB",
        retention="7 days",
        compression="gz",
        backtrace=True,
        diagnose=True,
    )
