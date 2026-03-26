# AGENTS.md

## Project Overview

BakiBounty is an advanced bug bounty automation framework for reconnaissance, probing, content discovery, and vulnerability scanning. Python 3.11+, async-first, modular pipeline architecture.

## Build / Run / Test Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run the CLI
python main.py --help
python main.py run example.com
python main.py run targets.txt -j 3          # parallel (3 targets)
python main.py doctor                          # check tool availability

# Run specific modules
python main.py recon subfinder example.com
python main.py probe httpx hosts.txt
python main.py discover katana urls.txt
python main.py scan nuclei targets.txt
python main.py scan ffuf https://example.com/FUZZ
python main.py report output/run_dir/

# Tests (pytest - no tests yet, this is the pattern to follow)
pip install pytest pytest-asyncio pytest-cov
pytest tests/                                  # run all tests
pytest tests/test_helpers.py                   # run single test file
pytest tests/test_helpers.py -k "test_resolve" # run single test by name
pytest tests/ -v --tb=short                    # verbose with short traceback
pytest tests/ --cov=. --cov-report=term-missing # coverage

# Lint / Format
pip install ruff
ruff check .                                   # lint
ruff check . --fix                             # lint + auto-fix
ruff format .                                  # format code
```

## Project Structure

```
main.py              # CLI entry (typer + rich), all subcommands defined here
config/
  config.yaml        # Default configuration
  schema.py          # Pydantic v2 models for config validation
modules/
  recon.py           # subfinder + amass wrappers, run_recon orchestrator
  probing.py         # httpx wrapper, run_probing orchestrator
  discovery.py       # katana wrapper, run_discovery orchestrator
  scanner.py         # nuclei + ffuf wrappers, run_scanner orchestrator
utils/
  helpers.py         # Tool resolver, async subprocess, JSON I/O, ModuleResult
  logger.py          # loguru + rich console setup
  notify.py          # Telegram/Discord notification senders
  report.py          # Markdown/HTML report generation (RunData aggregator)
output/              # Timestamped run directories: <target>_<timestamp>/
templates/           # Custom nuclei templates
```

## Code Style Guidelines

### Imports
- Use `from __future__ import annotations` at top of every file
- Group: stdlib, third-party, local (blank line between groups)
- Alphabetical within each group
- Use explicit imports, avoid `import *`

```python
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Optional

from loguru import logger
import httpx

from utils.helpers import ModuleResult, run_tool
```

### Types
- All function signatures must have type hints
- Use `Optional[X]` not `X | None` (Python 3.10 compat in some contexts)
- Use `Any` for config objects passed across modules (avoid circular imports)
- Pydantic models for all config validation (`config/schema.py`)
- Dataclasses for result containers (`ModuleResult`, `CommandResult`)

### Naming
- Functions: `snake_case`, async functions prefixed with action verb (`run_subfinder`, `run_nuclei`)
- Classes: `PascalCase` (`ModuleResult`, `BakiConfig`, `RunData`)
- Constants: `UPPER_SNAKE_CASE` (`_TOOL_ALIASES`)
- Private: prefix with `_` (`_parse_subfinder_result`, `_count_lines`)
- Config keys: `snake_case` in YAML, matching Pydantic field names

### Async Patterns
- Use `asyncio.create_subprocess_exec` for tool execution (in `helpers.py`)
- Use `asyncio.gather(*tasks)` for parallel module execution
- Use `asyncio.Semaphore` for concurrency control
- All module runners (`run_*`) are async, return `ModuleResult`

### Error Handling
- Tools return `CommandResult` with `.success`, `.timed_out`, `.stderr`
- Modules return `ModuleResult` with `.status`, `.errors` list
- Never raise from module runners; capture errors in `ModuleResult.errors`
- Use `loguru` logger: `logger.info()`, `logger.warning()`, `logger.error()`
- Graceful degradation: if tool missing, report error, continue pipeline

### Output / Logging
- Rich console for user-facing output (colored, formatted)
- Loguru for structured logging (file + stderr)
- JSON results via `orjson` (fast serialization)
- Output goes to `output/<target>_<timestamp>/` directory

### File Conventions
- Each module is self-contained, imports from `utils.helpers`
- Avoid circular imports: modules import from `utils`, never from `main.py`
- Docstrings: Google style with Args/Returns sections
- Section separators: `# -----------...` between logical groups

## Adding New Modules

1. Create `modules/new_module.py`
2. Implement `async def run_newthing(targets, *, config, timeout, ...) -> ModuleResult`
3. Add config model to `config/schema.py` under `ScanningConfig` or new section
4. Wire into `main.py` pipeline loop and add subcommand
5. Update `modules/__init__.py` exports
6. Results auto-saved to run directory via `ModuleResult.save()`

## Key Dependencies

- **typer**: CLI framework (commands, options, help generation)
- **rich**: Console output (tables, panels, progress, Live display)
- **pydantic v2**: Config validation with `BaseModel`, `Field` constraints
- **httpx**: Async HTTP client (notifications, future API calls)
- **loguru**: Structured logging with rotation
- **orjson**: Fast JSON serialization (10x faster than stdlib)
- **aiofiles**: Async file I/O (imported but not heavily used yet)

## Testing Guidelines

When writing tests (pytest):
- Test files: `tests/test_<module>.py`
- Async tests: use `@pytest.mark.asyncio` decorator
- Mock subprocess calls with `unittest.mock.AsyncMock`
- Test `ModuleResult` parsing with sample tool output
- Test config validation with valid/invalid YAML
- No network calls in unit tests; mock external APIs
