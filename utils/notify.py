"""
BakiBounty - Notification Module

Sends alerts via Telegram and Discord when findings match severity filter.
Configured via config.yaml under notifications.

Telegram: Bot API (sendMessage)
Discord: Webhook POST
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
from loguru import logger

# ---------------------------------------------------------------------------
# Message Formatting
# ---------------------------------------------------------------------------


def format_finding_telegram(finding: dict, target: str) -> str:
    """Format a finding for Telegram (MarkdownV2-safe plain text)."""
    sev = finding.get("severity", "info").upper()
    name = finding.get("name", finding.get("template", "Unknown"))
    host = finding.get("host", "")
    matched = finding.get("matched_at", "")
    cve = finding.get("cve", "")
    cvss = finding.get("cvss", "")

    icon = {"CRITICAL": "\U0001f6a8", "HIGH": "\u26a0\ufe0f"}.get(sev, "\U0001f4cb")

    lines = [
        f"{icon} [{sev}] BakiBounty Finding",
        "",
        f"Target: {target}",
        f"Finding: {name}",
        f"Severity: {sev}",
        f"Host: {host}",
    ]
    if matched:
        lines.append(f"Matched: {matched}")
    if cve:
        lines.append(f"CVE: {cve}")
    if cvss:
        lines.append(f"CVSS: {cvss}")

    return "\n".join(lines)


def format_finding_discord(finding: dict, target: str) -> dict:
    """Format a finding as a Discord embed."""
    sev = finding.get("severity", "info").upper()
    name = finding.get("name", finding.get("template", "Unknown"))
    host = finding.get("host", "")
    matched = finding.get("matched_at", "")
    cve = finding.get("cve", "")
    cvss = finding.get("cvss", "")

    color_map = {
        "CRITICAL": 0xFF0000,
        "HIGH": 0xFF8C00,
        "MEDIUM": 0xFFD700,
        "LOW": 0x808080,
        "INFO": 0x5865F2,
    }
    color = color_map.get(sev, 0x808080)

    icon = {"CRITICAL": "\U0001f6a8", "HIGH": "\u26a0\ufe0f"}.get(sev, "\U0001f4cb")

    fields = [
        {"name": "Target", "value": target, "inline": True},
        {"name": "Severity", "value": f"{icon} {sev}", "inline": True},
        {"name": "Host", "value": host or "N/A", "inline": True},
    ]

    if matched:
        fields.append({"name": "Matched At", "value": matched, "inline": False})
    if cve:
        fields.append({"name": "CVE", "value": cve, "inline": True})
    if cvss:
        fields.append({"name": "CVSS", "value": str(cvss), "inline": True})

    desc = finding.get("description", "")
    if desc and len(desc) > 300:
        desc = desc[:297] + "..."

    return {
        "embeds": [
            {
                "title": f"{icon} {name}",
                "description": desc or None,
                "color": color,
                "fields": fields,
                "footer": {"text": "BakiBounty"},
            }
        ]
    }


def format_summary_telegram(
    target: str,
    findings: list[dict],
    duration: float,
) -> str:
    """Format a scan summary for Telegram."""
    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    lines = [
        "\U0001f4ca BakiBounty Scan Complete",
        "",
        f"Target: {target}",
        f"Duration: {duration:.1f}s",
        f"Findings: {len(findings)}",
    ]

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            icon = {"CRITICAL": "\U0001f6a8", "HIGH": "\u26a0\ufe0f"}.get(sev, "")
            lines.append(f"  {icon} {sev}: {count}")

    return "\n".join(lines)


def format_summary_discord(
    target: str,
    findings: list[dict],
    duration: float,
) -> dict:
    """Format a scan summary as a Discord embed."""
    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    has_critical = severity_counts.get("CRITICAL", 0) > 0
    color = 0xFF0000 if has_critical else 0x00FF00

    fields = [
        {"name": "Target", "value": target, "inline": True},
        {"name": "Duration", "value": f"{duration:.1f}s", "inline": True},
        {"name": "Total Findings", "value": str(len(findings)), "inline": True},
    ]

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            icon = {"CRITICAL": "\U0001f6a8", "HIGH": "\u26a0\ufe0f"}.get(sev, "")
            fields.append(
                {
                    "name": f"{icon} {sev}",
                    "value": str(count),
                    "inline": True,
                }
            )

    return {
        "embeds": [
            {
                "title": "\U0001f4ca BakiBounty Scan Complete",
                "color": color,
                "fields": fields,
                "footer": {"text": "BakiBounty"},
            }
        ]
    }


# ---------------------------------------------------------------------------
# Senders
# ---------------------------------------------------------------------------


async def send_telegram(
    message: str,
    bot_token: str,
    chat_id: str,
) -> bool:
    """Send a text message via Telegram Bot API.

    Returns True on success.
    """
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(url, json=payload)
            if resp.status_code == 200:
                logger.debug("Telegram message sent")
                return True
            else:
                logger.error(
                    "Telegram API error {}: {}", resp.status_code, resp.text[:200]
                )
                return False
    except Exception as exc:
        logger.error("Telegram send failed: {}", exc)
        return False


async def send_discord(
    payload: dict,
    webhook_url: str,
) -> bool:
    """Send a message/embed via Discord webhook.

    Returns True on success.
    """
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(webhook_url, json=payload)
            if resp.status_code in (200, 204):
                logger.debug("Discord message sent")
                return True
            else:
                logger.error(
                    "Discord webhook error {}: {}", resp.status_code, resp.text[:200]
                )
                return False
    except Exception as exc:
        logger.error("Discord send failed: {}", exc)
        return False


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


async def notify_finding(
    finding: dict,
    target: str,
    config: Any,
) -> None:
    """Send notification for a single finding if it matches severity filter."""
    if not config.notifications.enabled:
        return

    sev = finding.get("severity", "info").lower()
    notify_levels = [s.value for s in config.notifications.on]

    if sev not in notify_levels:
        return

    tasks: list[Any] = []

    # Telegram
    tg = config.notifications.telegram
    if tg.bot_token and tg.chat_id:
        msg = format_finding_telegram(finding, target)
        tasks.append(send_telegram(msg, tg.bot_token, tg.chat_id))

    # Discord
    dc = config.notifications.discord
    if dc.webhook_url:
        payload = format_finding_discord(finding, target)
        tasks.append(send_discord(payload, dc.webhook_url))

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


async def notify_summary(
    target: str,
    findings: list[dict],
    duration: float,
    config: Any,
) -> None:
    """Send scan summary notification."""
    if not config.notifications.enabled:
        return

    tasks: list[Any] = []

    # Telegram
    tg = config.notifications.telegram
    if tg.bot_token and tg.chat_id:
        msg = format_summary_telegram(target, findings, duration)
        tasks.append(send_telegram(msg, tg.bot_token, tg.chat_id))

    # Discord
    dc = config.notifications.discord
    if dc.webhook_url:
        payload = format_summary_discord(target, findings, duration)
        tasks.append(send_discord(payload, dc.webhook_url))

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
