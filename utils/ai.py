"""
BakiBounty - AI Analysis Module

Integrates AI providers for vulnerability analysis:
- Kilo Code: Custom AI API
- OpenAI: GPT models
- Anthropic: Claude models
- Custom: Any OpenAI-compatible API

Features:
- Auto-analyze critical/high findings
- Risk assessment + remediation suggestions
- Exploitation difficulty rating
- Batch analysis support
"""

from __future__ import annotations

import os
from typing import Any, Optional

import httpx
from loguru import logger

# ---------------------------------------------------------------------------
# Provider Config
# ---------------------------------------------------------------------------

# Default API endpoints per provider
_PROVIDER_ENDPOINTS: dict[str, str] = {
    "kilo": "https://api.kilocode.ai/v1/chat/completions",
    "openai": "https://api.openai.com/v1/chat/completions",
    "anthropic": "https://api.anthropic.com/v1/messages",
    "minimax": "https://api.minimax.chat/v1/chat/completions",
    "groq": "https://api.groq.com/openai/v1/chat/completions",
    "together": "https://api.together.xyz/v1/chat/completions",
    "deepseek": "https://api.deepseek.com/v1/chat/completions",
    "custom": "",  # must set base_url in config
}

# Free/cheap models per provider
_PROVIDER_FREE_MODELS: dict[str, str] = {
    "kilo": "grok-code-fast-1",
    "minimax": "MiniMax-M2.5",
    "groq": "llama-3.1-70b-versatile",
    "together": "meta-llama/Llama-3-70b-chat-hf",
    "deepseek": "deepseek-chat",
}


def get_api_key(config: Any) -> Optional[str]:
    """Get API key from config or environment variable."""
    # Priority: config.ai.api_key > BAKIBOUNTY_AI_KEY env var
    if config.ai.api_key:
        return config.ai.api_key
    return os.environ.get("BAKIBOUNTY_AI_KEY")


def get_base_url(config: Any) -> str:
    """Get API base URL from config or provider defaults."""
    if config.ai.base_url:
        return config.ai.base_url
    return _PROVIDER_ENDPOINTS.get(config.ai.provider, "")


def is_enabled(config: Any) -> bool:
    """Check if AI analysis is enabled and configured."""
    if not config.ai.enabled:
        return False
    api_key = get_api_key(config)
    if not api_key:
        logger.warning("AI enabled but no API key set")
        return False
    base_url = get_base_url(config)
    if not base_url:
        logger.warning(
            "AI enabled but no base URL for provider: {}", config.ai.provider
        )
        return False
    return True


# ---------------------------------------------------------------------------
# Prompt Templates
# ---------------------------------------------------------------------------

ANALYSIS_SYSTEM_PROMPT = """You are a senior cybersecurity analyst specializing in bug bounty and penetration testing.
Analyze the provided vulnerability finding and return a JSON response with this exact structure:
{
  "risk_level": "critical|high|medium|low",
  "summary": "1-2 sentence summary of the vulnerability",
  "impact": "What could an attacker achieve by exploiting this?",
  "exploitation_difficulty": "easy|medium|hard",
  "remediation": ["Step 1", "Step 2", ...],
  "references": ["URL1", "URL2"],
  "cvss_notes": "Any CVSS scoring context or adjustments",
  "bug_bounty_tips": "Tips for reporting this finding"
}
Be concise, actionable, and focused on real-world impact."""


def build_finding_prompt(finding: dict) -> str:
    """Build analysis prompt for a single finding."""
    lines = [
        "Analyze this security finding:",
        "",
        f"Template ID: {finding.get('template', 'N/A')}",
        f"Finding Name: {finding.get('name', 'N/A')}",
        f"Severity: {finding.get('severity', 'N/A')}",
        f"Host: {finding.get('host', 'N/A')}",
        f"Matched At: {finding.get('matched_at', 'N/A')}",
    ]

    if finding.get("cve"):
        lines.append(f"CVE: {finding['cve']}")
    if finding.get("cvss"):
        lines.append(f"CVSS Score: {finding['cvss']}")
    if finding.get("cwe"):
        lines.append(f"CWE: {finding['cwe']}")
    if finding.get("description"):
        lines.append(f"Description: {finding['description']}")
    if finding.get("evidence"):
        evidence = finding["evidence"]
        if isinstance(evidence, list):
            evidence = ", ".join(str(e) for e in evidence[:5])
        lines.append(f"Evidence: {evidence}")
    if finding.get("tags"):
        tags = finding["tags"]
        if isinstance(tags, list):
            tags = ", ".join(tags)
        lines.append(f"Tags: {tags}")
    if finding.get("metadata"):
        lines.append(f"Metadata: {finding['metadata']}")

    return "\n".join(lines)


def build_batch_prompt(findings: list[dict]) -> str:
    """Build analysis prompt for multiple findings."""
    lines = [
        f"Analyze these {len(findings)} security findings and provide analysis for each:",
        "",
    ]

    for i, finding in enumerate(findings[:10], 1):  # Cap at 10
        lines.append(f"--- Finding {i} ---")
        lines.append(f"Template: {finding.get('template', 'N/A')}")
        lines.append(f"Name: {finding.get('name', 'N/A')}")
        lines.append(f"Severity: {finding.get('severity', 'N/A')}")
        lines.append(f"Host: {finding.get('host', 'N/A')}")
        if finding.get("cve"):
            lines.append(f"CVE: {finding['cve']}")
        if finding.get("description"):
            desc = finding["description"]
            if len(desc) > 200:
                desc = desc[:197] + "..."
            lines.append(f"Description: {desc}")
        lines.append("")

    lines.append("Return a JSON array with analysis for each finding.")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# API Callers
# ---------------------------------------------------------------------------


async def call_kilo_api(
    prompt: str,
    api_key: str,
    model: str,
    max_tokens: int,
    temperature: float,
    base_url: str,
) -> Optional[str]:
    """Call Kilo Code API (OpenAI-compatible format)."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": ANALYSIS_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": max_tokens,
        "temperature": temperature,
    }

    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(base_url, headers=headers, json=payload)

            if resp.status_code == 200:
                data = resp.json()
                return data["choices"][0]["message"]["content"]
            else:
                logger.error("Kilo API error {}: {}", resp.status_code, resp.text[:200])
                return None

    except Exception as exc:
        logger.error("Kilo API call failed: {}", exc)
        return None


async def call_openai_api(
    prompt: str,
    api_key: str,
    model: str,
    max_tokens: int,
    temperature: float,
) -> Optional[str]:
    """Call OpenAI API."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": ANALYSIS_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": max_tokens,
        "temperature": temperature,
    }

    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=payload,
            )

            if resp.status_code == 200:
                data = resp.json()
                return data["choices"][0]["message"]["content"]
            else:
                logger.error(
                    "OpenAI API error {}: {}", resp.status_code, resp.text[:200]
                )
                return None

    except Exception as exc:
        logger.error("OpenAI API call failed: {}", exc)
        return None


async def call_anthropic_api(
    prompt: str,
    api_key: str,
    model: str,
    max_tokens: int,
    temperature: float,
) -> Optional[str]:
    """Call Anthropic API."""
    headers = {
        "x-api-key": api_key,
        "Content-Type": "application/json",
        "anthropic-version": "2023-06-01",
    }

    payload = {
        "model": model,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "system": ANALYSIS_SYSTEM_PROMPT,
        "messages": [
            {"role": "user", "content": prompt},
        ],
    }

    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers=headers,
                json=payload,
            )

            if resp.status_code == 200:
                data = resp.json()
                return data["content"][0]["text"]
            else:
                logger.error(
                    "Anthropic API error {}: {}", resp.status_code, resp.text[:200]
                )
                return None

    except Exception as exc:
        logger.error("Anthropic API call failed: {}", exc)
        return None


# ---------------------------------------------------------------------------
# Main Analysis Functions
# ---------------------------------------------------------------------------


async def analyze_finding(
    finding: dict,
    config: Any,
) -> Optional[dict]:
    """Analyze a single vulnerability finding with AI.

    Returns dict with analysis or None on failure.
    """
    if not is_enabled(config):
        return None

    api_key = get_api_key(config)
    base_url = get_base_url(config)
    provider = config.ai.provider
    model = config.ai.model
    max_tokens = config.ai.max_tokens
    temperature = config.ai.temperature

    prompt = build_finding_prompt(finding)

    # Call appropriate provider
    if provider in ("kilo", "custom"):
        response = await call_kilo_api(
            prompt, api_key, model, max_tokens, temperature, base_url
        )
    elif provider == "openai":
        response = await call_openai_api(
            prompt, api_key, model, max_tokens, temperature
        )
    elif provider == "anthropic":
        response = await call_anthropic_api(
            prompt, api_key, model, max_tokens, temperature
        )
    else:
        logger.error("Unknown AI provider: {}", provider)
        return None

    if not response:
        return None

    # Try to parse JSON from response
    import orjson

    try:
        # Extract JSON from response (may have markdown code blocks)
        json_str = response.strip()
        if json_str.startswith("```"):
            json_str = json_str.split("\n", 1)[1]
            if json_str.endswith("```"):
                json_str = json_str.rsplit("```", 1)[0]
        json_str = json_str.strip()

        analysis = orjson.loads(json_str)
        analysis["_raw_response"] = response
        return analysis

    except orjson.JSONDecodeError:
        # Return raw response if JSON parsing fails
        logger.warning("Could not parse AI response as JSON")
        return {"summary": response, "_raw_response": response}


async def analyze_findings_batch(
    findings: list[dict],
    config: Any,
) -> list[dict]:
    """Analyze multiple findings with AI.

    Returns list of findings with 'ai_analysis' field added.
    """
    if not is_enabled(config):
        return findings

    severity_filter = [s.value for s in config.ai.analyze_severity]

    # Filter findings that need analysis
    to_analyze = [f for f in findings if f.get("severity", "info") in severity_filter]

    if not to_analyze:
        logger.info("No findings match AI analysis severity filter")
        return findings

    logger.info(
        "Analyzing {} findings with AI (provider={})",
        len(to_analyze),
        config.ai.provider,
    )

    # Analyze each finding (parallel with limit)
    import asyncio

    sem = asyncio.Semaphore(3)  # Max 3 concurrent API calls

    async def _analyze_one(finding: dict) -> dict:
        async with sem:
            analysis = await analyze_finding(finding, config)
            if analysis:
                finding["ai_analysis"] = analysis
            return finding

    analyzed = await asyncio.gather(
        *[_analyze_one(f) for f in to_analyze],
        return_exceptions=True,
    )

    # Merge back with original findings
    analyzed_map: dict[str, dict] = {}
    for f in analyzed:
        if isinstance(f, dict):
            key = f"{f.get('template', '')}:{f.get('host', '')}"
            analyzed_map[key] = f

    result: list[dict] = []
    for f in findings:
        key = f"{f.get('template', '')}:{f.get('host', '')}"
        if key in analyzed_map:
            result.append(analyzed_map[key])
        else:
            result.append(f)

    return result


async def analyze_run(
    run_dir: Any,
    config: Any,
) -> Optional[dict]:
    """Analyze all findings in a run directory.

    Returns summary dict or None.
    """
    from pathlib import Path

    from utils.helpers import load_json, save_json

    run_dir = Path(run_dir)

    # Load scanner results
    scanner_file = run_dir / "scanner.json"
    if not scanner_file.is_file():
        logger.error("No scanner.json found in {}", run_dir)
        return None

    data = load_json(scanner_file)
    findings = data.get("items", [])

    if not findings:
        logger.info("No findings to analyze")
        return {"findings": 0, "analyzed": 0}

    # Analyze
    analyzed_findings = await analyze_findings_batch(findings, config)

    # Save enriched results
    data["items"] = analyzed_findings
    save_json(data, scanner_file)

    # Count analyses
    analyzed_count = sum(1 for f in analyzed_findings if "ai_analysis" in f)

    logger.info(
        "AI analysis complete: {}/{} findings analyzed", analyzed_count, len(findings)
    )

    return {
        "findings": len(findings),
        "analyzed": analyzed_count,
    }
