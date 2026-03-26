"""
BakiBounty - Bug Bounty Scope Checker

Check if a target is in-scope for bug bounty programs.
Queries:
- HackerOne (GraphQL API)
- Bugcrowd (programs API)
- Vulners (CVE lookup)
- Built-in known programs list

Shows: scope, severity levels, bounty ranges, rules
"""

from __future__ import annotations

from typing import Any, Optional

import httpx
from loguru import logger

# ---------------------------------------------------------------------------
# Known Bug Bounty Programs (popular ones)
# ---------------------------------------------------------------------------

KNOWN_PROGRAMS: dict[str, list[dict]] = {
    # Major tech companies
    "google.com": [
        {
            "name": "Google",
            "platform": "bugcrowd",
            "url": "https://bugcrowd.com/google",
            "bounty": True,
        },
    ],
    "facebook.com": [
        {
            "name": "Meta",
            "platform": "hackerone",
            "url": "https://hackerone.com/facebook",
            "bounty": True,
        },
    ],
    "twitter.com": [
        {
            "name": "X (Twitter)",
            "platform": "hackerone",
            "url": "https://hackerone.com/twitter",
            "bounty": True,
        },
    ],
    "github.com": [
        {
            "name": "GitHub",
            "platform": "hackerone",
            "url": "https://hackerone.com/github",
            "bounty": True,
        },
    ],
    "shopify.com": [
        {
            "name": "Shopify",
            "platform": "hackerone",
            "url": "https://hackerone.com/shopify",
            "bounty": True,
        },
    ],
    "reddit.com": [
        {
            "name": "Reddit",
            "platform": "hackerone",
            "url": "https://hackerone.com/reddit",
            "bounty": True,
        },
    ],
    "uber.com": [
        {
            "name": "Uber",
            "platform": "hackerone",
            "url": "https://hackerone.com/uber",
            "bounty": True,
        },
    ],
    "spotify.com": [
        {
            "name": "Spotify",
            "platform": "hackerone",
            "url": "https://hackerone.com/spotify",
            "bounty": True,
        },
    ],
    "twitch.tv": [
        {
            "name": "Twitch",
            "platform": "hackerone",
            "url": "https://hackerone.com/twitch",
            "bounty": True,
        },
    ],
    "dropbox.com": [
        {
            "name": "Dropbox",
            "platform": "hackerone",
            "url": "https://hackerone.com/dropbox",
            "bounty": True,
        },
    ],
    "slack.com": [
        {
            "name": "Slack",
            "platform": "hackerone",
            "url": "https://hackerone.com/slack",
            "bounty": True,
        },
    ],
    "cloudflare.com": [
        {
            "name": "Cloudflare",
            "platform": "hackerone",
            "url": "https://hackerone.com/cloudflare",
            "bounty": True,
        },
    ],
    "hackerone.com": [
        {
            "name": "HackerOne",
            "platform": "hackerone",
            "url": "https://hackerone.com/security",
            "bounty": True,
        },
    ],
    "bugcrowd.com": [
        {
            "name": "Bugcrowd",
            "platform": "bugcrowd",
            "url": "https://bugcrowd.com/bugcrowd",
            "bounty": True,
        },
    ],
    "wordpress.com": [
        {
            "name": "Automattic",
            "platform": "hackerone",
            "url": "https://hackerone.com/automattic",
            "bounty": True,
        },
    ],
    "mozilla.org": [
        {
            "name": "Mozilla",
            "platform": "hackerone",
            "url": "https://hackerone.com/mozilla",
            "bounty": True,
        },
    ],
    "yahoo.com": [
        {
            "name": "Yahoo",
            "platform": "hackerone",
            "url": "https://hackerone.com/yahoo",
            "bounty": True,
        },
    ],
    "linkedin.com": [
        {
            "name": "LinkedIn",
            "platform": "hackerone",
            "url": "https://hackerone.com/linkedin",
            "bounty": True,
        },
    ],
    "paypal.com": [
        {
            "name": "PayPal",
            "platform": "hackerone",
            "url": "https://hackerone.com/paypal",
            "bounty": True,
        },
    ],
    "stripe.com": [
        {
            "name": "Stripe",
            "platform": "hackerone",
            "url": "https://hackerone.com/stripe",
            "bounty": True,
        },
    ],
    "amazon.com": [
        {
            "name": "Amazon",
            "platform": "hackerone",
            "url": "https://hackerone.com/amazon",
            "bounty": True,
        },
    ],
    "netflix.com": [
        {
            "name": "Netflix",
            "platform": "bugcrowd",
            "url": "https://bugcrowd.com/netflix",
            "bounty": True,
        },
    ],
    "apple.com": [
        {
            "name": "Apple",
            "platform": "hackerone",
            "url": "https://hackerone.com/apple",
            "bounty": True,
        },
    ],
    "microsoft.com": [
        {
            "name": "Microsoft",
            "platform": "hackerone",
            "url": "https://hackerone.com/microsoft",
            "bounty": True,
        },
    ],
    "adobe.com": [
        {
            "name": "Adobe",
            "platform": "hackerone",
            "url": "https://hackerone.com/adobe",
            "bounty": True,
        },
    ],
    "cisco.com": [
        {
            "name": "Cisco",
            "platform": "hackerone",
            "url": "https://hackerone.com/cisco",
            "bounty": True,
        },
    ],
    "okta.com": [
        {
            "name": "Okta",
            "platform": "hackerone",
            "url": "https://hackerone.com/okta",
            "bounty": True,
        },
    ],
    "atlassian.com": [
        {
            "name": "Atlassian",
            "platform": "bugcrowd",
            "url": "https://bugcrowd.com/atlassian",
            "bounty": True,
        },
    ],
    "zoom.us": [
        {
            "name": "Zoom",
            "platform": "hackerone",
            "url": "https://hackerone.com/zoom",
            "bounty": True,
        },
    ],
    "samsung.com": [
        {
            "name": "Samsung",
            "platform": "hackerone",
            "url": "https://hackerone.com/samsung",
            "bounty": True,
        },
    ],
    "tiktok.com": [
        {
            "name": "TikTok",
            "platform": "hackerone",
            "url": "https://hackerone.com/tiktok",
            "bounty": True,
        },
    ],
    "instagram.com": [
        {
            "name": "Instagram (Meta)",
            "platform": "hackerone",
            "url": "https://hackerone.com/facebook",
            "bounty": True,
        },
    ],
    "whatsapp.com": [
        {
            "name": "WhatsApp (Meta)",
            "platform": "hackerone",
            "url": "https://hackerone.com/whatsapp",
            "bounty": True,
        },
    ],
    "telegram.org": [
        {
            "name": "Telegram",
            "platform": "hackerone",
            "url": "https://hackerone.com/telegram",
            "bounty": True,
        },
    ],
    "wordpress.org": [
        {
            "name": "WordPress.org",
            "platform": "hackerone",
            "url": "https://hackerone.com/wordpress",
            "bounty": True,
        },
    ],
    "openai.com": [
        {
            "name": "OpenAI",
            "platform": "hackerone",
            "url": "https://hackerone.com/openai",
            "bounty": True,
        },
    ],
    "binance.com": [
        {
            "name": "Binance",
            "platform": "hackerone",
            "url": "https://hackerone.com/binance",
            "bounty": True,
        },
    ],
    "coinbase.com": [
        {
            "name": "Coinbase",
            "platform": "hackerone",
            "url": "https://hackerone.com/coinbase",
            "bounty": True,
        },
    ],
    "robinhood.com": [
        {
            "name": "Robinhood",
            "platform": "hackerone",
            "url": "https://hackerone.com/robinhood",
            "bounty": True,
        },
    ],
    "doordash.com": [
        {
            "name": "DoorDash",
            "platform": "hackerone",
            "url": "https://hackerone.com/doordash",
            "bounty": True,
        },
    ],
    "lyft.com": [
        {
            "name": "Lyft",
            "platform": "hackerone",
            "url": "https://hackerone.com/lyft",
            "bounty": True,
        },
    ],
    "airbnb.com": [
        {
            "name": "Airbnb",
            "platform": "hackerone",
            "url": "https://hackerone.com/airbnb",
            "bounty": True,
        },
    ],
}


# ---------------------------------------------------------------------------
# HackerOne GraphQL API
# ---------------------------------------------------------------------------

HACKERONE_GRAPHQL = "https://hackerone.com/graphql"


async def search_hackerone_programs(domain: str) -> list[dict]:
    """Search HackerOne programs via GraphQL.

    Args:
        domain: Domain or keyword to search

    Returns:
        List of matching programs
    """
    query = """
    query($query: String!, $first: Int!) {
        search(
            query: $query
            type: TEAM
            first: $first
            product_area: "directory"
            product_feature: "search"
        ) {
            nodes {
                ... on TeamSearchResult {
                    team {
                        name
                        handle
                        url: url
                        offers_bounties
                        state
                        submission_state
                    }
                }
            }
        }
    }
    """

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                HACKERONE_GRAPHQL,
                json={"query": query, "variables": {"query": domain, "first": 10}},
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )

            if resp.status_code == 200:
                data = resp.json()
                nodes = data.get("data", {}).get("search", {}).get("nodes", [])

                matches = []
                for node in nodes:
                    if not node:
                        continue
                    team = node.get("team", node)
                    if not team:
                        continue

                    matches.append(
                        {
                            "name": team.get("name", ""),
                            "handle": team.get("handle", ""),
                            "url": team.get("url")
                            or f"https://hackerone.com/{team.get('handle', '')}",
                            "platform": "hackerone",
                            "offers_bounties": team.get("offers_bounties", False),
                            "state": team.get("state", "open"),
                        }
                    )

                return matches

            logger.debug(
                "HackerOne GraphQL error: {} {}", resp.status_code, resp.text[:200]
            )
            return []

    except Exception as exc:
        logger.debug("HackerOne search failed for {}: {}", domain, exc)
        return []


# ---------------------------------------------------------------------------
# Bugcrowd API
# ---------------------------------------------------------------------------


async def search_bugcrowd_programs(domain: str) -> list[dict]:
    """Search Bugcrowd programs.

    Uses the public programs endpoint.
    """
    url = "https://bugcrowd.com/programs.json"

    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
            resp = await client.get(
                url,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                },
            )

            if resp.status_code != 200:
                logger.debug("Bugcrowd API error: {}", resp.status_code)
                return []

            data = resp.json()
            programs = data.get("programs", [])

            domain_lower = domain.lower()
            matches = []
            for p in programs:
                name = (p.get("name") or "").lower()
                code = (p.get("code") or "").lower()
                if domain_lower in name or domain_lower in code:
                    matches.append(
                        {
                            "name": p.get("name", ""),
                            "handle": p.get("code", ""),
                            "url": f"https://bugcrowd.com/{p.get('code', '')}",
                            "platform": "bugcrowd",
                            "offers_bounties": (p.get("max_payout") or 0) > 0,
                            "max_payout": p.get("max_payout"),
                            "state": "open"
                            if p.get("participation") == "open"
                            else "private",
                        }
                    )

            return matches[:10]

    except Exception as exc:
        logger.debug("Bugcrowd search failed for {}: {}", domain, exc)
        return []


# ---------------------------------------------------------------------------
# Vulners - CVE/Vulnerability Lookup
# ---------------------------------------------------------------------------


async def lookup_vulners(domain: str, api_key: Optional[str] = None) -> dict[str, Any]:
    """Look up known vulnerabilities for a domain via Vulners.

    Args:
        domain: Target domain
        api_key: Vulners API key (optional)

    Returns:
        Dict with vulnerability info
    """
    result: dict[str, Any] = {
        "domain": domain,
        "total_vulns": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "top_cves": [],
    }

    url = "https://vulners.com/api/v3/search/lucene/"

    payload = {
        "query": f'affectedSoftware.host:"{domain}" OR title:"{domain}"',
        "size": 50,
    }

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["X-Vulners-Api-Key"] = api_key

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(url, json=payload, headers=headers)

            if resp.status_code != 200:
                return result

            data = resp.json()
            vulns = data.get("data", {}).get("search", [])

            result["total_vulns"] = len(vulns)

            for v in vulns[:20]:
                source = v.get("_source", {})
                cvss = source.get("cvss", {})
                score = cvss.get("score", 0)

                if score >= 9.0:
                    result["critical"] += 1
                elif score >= 7.0:
                    result["high"] += 1
                elif score >= 4.0:
                    result["medium"] += 1
                else:
                    result["low"] += 1

                cve_list = source.get("cvelist", [])
                if cve_list:
                    result["top_cves"].append(
                        {
                            "cve": cve_list[0],
                            "title": source.get("title", "")[:100],
                            "cvss": score,
                        }
                    )

            return result

    except Exception as exc:
        logger.debug("Vulners lookup failed for {}: {}", domain, exc)
        return result


# ---------------------------------------------------------------------------
# Scope Analysis
# ---------------------------------------------------------------------------


async def check_target_scope(
    domain: str,
    vulners_key: Optional[str] = None,
) -> dict[str, Any]:
    """Check if a domain is in any bug bounty program.

    Args:
        domain: Target domain to check
        vulners_key: Optional Vulners API key

    Returns:
        Dict with scope information
    """
    import asyncio

    result: dict[str, Any] = {
        "domain": domain,
        "in_scope": False,
        "programs": [],
        "platforms_checked": ["hackerone", "bugcrowd", "builtin"],
        "bounty_available": False,
        "vulners": None,
    }

    # Check built-in list first (instant)
    domain_clean = domain.lower().replace("www.", "")
    if domain_clean in KNOWN_PROGRAMS:
        result["in_scope"] = True
        result["programs"] = KNOWN_PROGRAMS[domain_clean]
        result["bounty_available"] = True

    # Search online platforms in parallel
    h1_task = asyncio.create_task(search_hackerone_programs(domain))
    bc_task = asyncio.create_task(search_bugcrowd_programs(domain))
    vul_task = asyncio.create_task(lookup_vulners(domain, vulners_key))

    h1_results, bc_results, vul_results = await asyncio.gather(
        h1_task, bc_task, vul_task, return_exceptions=True
    )

    if isinstance(h1_results, list) and h1_results:
        result["in_scope"] = True
        for p in h1_results:
            if p not in result["programs"]:
                result["programs"].append(p)
        if any(p.get("offers_bounties") for p in h1_results):
            result["bounty_available"] = True

    if isinstance(bc_results, list) and bc_results:
        result["in_scope"] = True
        for p in bc_results:
            if p not in result["programs"]:
                result["programs"].append(p)
        if any(p.get("offers_bounties") for p in bc_results):
            result["bounty_available"] = True

    if isinstance(vul_results, dict):
        result["vulners"] = vul_results

    return result


async def check_target_multi(
    targets: list[str],
    vulners_key: Optional[str] = None,
) -> list[dict]:
    """Check scope for multiple targets."""
    import asyncio

    sem = asyncio.Semaphore(3)

    async def _check_one(domain: str) -> dict:
        async with sem:
            return await check_target_scope(domain, vulners_key)

    results = await asyncio.gather(
        *[_check_one(t) for t in targets],
        return_exceptions=True,
    )

    return [r for r in results if isinstance(r, dict)]
