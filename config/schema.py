"""
BakiBounty - Configuration Schema (Pydantic v2)

Validates config/config.yaml at runtime.
All fields have sensible defaults so the tool works out of the box.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class AmassMode(str, Enum):
    enum = "enum"
    intel = "intel"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class OutputFormat(str, Enum):
    json = "json"
    markdown = "markdown"
    html = "html"


class NotifyOn(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


# ---------------------------------------------------------------------------
# Sub-schemas
# ---------------------------------------------------------------------------


class GeneralConfig(BaseModel):
    threads: int = Field(default=20, ge=1, le=500)
    rate_limit: int = Field(default=150, ge=1, description="Requests/sec cap")
    timeout: int = Field(default=30, ge=5, le=600, description="Per-tool timeout (s)")
    retry: int = Field(default=2, ge=0, le=5)
    verbose: bool = False


class ToolsConfig(BaseModel):
    subfinder: Optional[Path] = None
    amass: Optional[Path] = None
    httpx: Optional[Path] = None
    nuclei: Optional[Path] = None
    katana: Optional[Path] = None
    ffuf: Optional[Path] = None
    naabu: Optional[Path] = None


class SubfinderConfig(BaseModel):
    all_sources: bool = True
    recursive: bool = True


class AmassConfig(BaseModel):
    mode: AmassMode = AmassMode.enum


class ReconConfig(BaseModel):
    sources: list[str] = Field(default=["subfinder"])
    subfinder: SubfinderConfig = SubfinderConfig()
    amass: AmassConfig = AmassConfig()


class HttpxConfig(BaseModel):
    status_code: bool = True
    tech_detect: bool = True
    content_length: bool = True
    title: bool = True
    favicon: bool = True
    response_time: bool = True
    follow_redirects: bool = True


class ProbingConfig(BaseModel):
    httpx: HttpxConfig = HttpxConfig()


class KatanaConfig(BaseModel):
    depth: int = Field(default=3, ge=1, le=10)
    js_crawl: bool = True
    field_scope: str = "rdn"
    strategy: str = "breadth-first"


class DiscoveryConfig(BaseModel):
    katana: KatanaConfig = KatanaConfig()


class NucleiConfig(BaseModel):
    severity: list[Severity] = Field(
        default=[Severity.critical, Severity.high, Severity.medium]
    )
    templates_dir: Optional[Path] = None
    custom_templates_dir: Path = Path("templates/")
    concurrency: int = Field(default=25, ge=1, le=200)
    rate_limit: int = Field(default=150, ge=1)
    headless: bool = False


class FfufConfig(BaseModel):
    wordlist: Path = Path("/usr/share/seclists/Discovery/Web-Content/common.txt")
    extensions: list[str] = Field(default=[".php", ".asp", ".aspx", ".jsp", ".html"])
    match_codes: list[int] = Field(
        default=[200, 204, 301, 302, 307, 401, 403, 405, 500]
    )
    threads: int = Field(default=40, ge=1, le=500)
    recursion_depth: int = Field(default=2, ge=0, le=5)


class ScanningConfig(BaseModel):
    nuclei: NucleiConfig = NucleiConfig()
    ffuf: FfufConfig = FfufConfig()


class OutputConfig(BaseModel):
    dir: Path = Path("output/")
    formats: list[OutputFormat] = Field(
        default=[OutputFormat.json, OutputFormat.markdown]
    )
    compress: bool = False


class TelegramConfig(BaseModel):
    bot_token: Optional[str] = None
    chat_id: Optional[str] = None


class DiscordConfig(BaseModel):
    webhook_url: Optional[str] = None


class NotificationsConfig(BaseModel):
    enabled: bool = False
    telegram: TelegramConfig = TelegramConfig()
    discord: DiscordConfig = DiscordConfig()
    on: list[NotifyOn] = Field(default=[NotifyOn.critical, NotifyOn.high])


# ---------------------------------------------------------------------------
# Root config
# ---------------------------------------------------------------------------


class BakiConfig(BaseModel):
    """Top-level configuration schema for BakiBounty."""

    general: GeneralConfig = GeneralConfig()
    tools: ToolsConfig = ToolsConfig()
    recon: ReconConfig = ReconConfig()
    probing: ProbingConfig = ProbingConfig()
    discovery: DiscoveryConfig = DiscoveryConfig()
    scanning: ScanningConfig = ScanningConfig()
    output: OutputConfig = OutputConfig()
    notifications: NotificationsConfig = NotificationsConfig()

    class Config:
        extra = "ignore"
