"""
BakiBounty - Bug Bounty Scope Checker

Check if a target is in-scope for bug bounty programs.
Queries public APIs from:
- HackerOne (GraphQL)
- Bugcrowd (public programs page)
- Intigriti (public programs)

Shows: scope, severity levels, bounty ranges, rules
"""

from __future__ import annotations

from typing import Any, Optional

import httpx
from loguru import logger


# ---------------------------------------------------------------------------
# HackerOne
# ---------------------------------------------------------------------------

HACKERONE_GRAPHQL = "https://hackerone.com/graphql"


async def query_hackerone(handle: str) -> Optional[dict]:
    """Query HackerOne program by handle.

    Args:
        handle: Program handle (e.g. "shopify", "twitter")

    Returns:
        Program info dict or None
    """
    query = """
    query($handle: String!) {
        team(handle: $handle) {
            name
            handle
            url
            profile_picture
            about
            website
            offers_bounties
            allows_biscience
            triage_active
            state
            submission_state
            policy
            structured_scope_versions(
                first: 100
                eligible_for_submission: true
            ) {
                edges {
                    node {
                        asset_identifier
                        asset_type
                        eligible_for_submission
                        eligible_for_bounty
                        instruction
                        max_severity
                        confidentiality_requirement
                        integrity_requirement
                        availability_requirement
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
                json={"query": query, "variables": {"handle": handle}},
                headers={"Accept": "application/json"},
            )

            if resp.status_code == 200:
                data = resp.json()
                return data.get("data", {}).get("team")
            else:
                logger.debug("HackerOne API error for {}: {}", handle, resp.status_code)
                return None

    except Exception as exc:
        logger.debug("HackerOne query failed for {}: {}", handle, exc)
        return None


async def search_hackerone_programs(domain: str) -> list[dict]:
    """Search HackerOne programs by domain/keyword.

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
        ) {
            nodes {
                ... on Team {
                    name
                    handle
                    url
                    offers_bounties
                    state
                    submission_state
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
                headers={"Accept": "application/json"},
            )

            if resp.status_code == 200:
                data = resp.json()
                nodes = data.get("data", {}).get("search", {}).get("nodes", [])
                return [n for n in nodes if n]

            return []

    except Exception as exc:
        logger.debug("HackerOne search failed for {}: {}", domain, exc)
        return []


# ---------------------------------------------------------------------------
# Bugcrowd
# ---------------------------------------------------------------------------


async def search_bugcrowd_programs(domain: str) -> list[dict]:
    """Search Bugcrowd programs (public API).

    Note: Bugcrowd doesn't have a public API, so we scrape the programs page.
    This is best-effort and may break if they change their site.
    """
    url = f"https://bugcrowd.com/programs.json"

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                url,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "Mozilla/5.0",
                },
            )

            if resp.status_code == 200:
                data = resp.json()
                programs = data.get("programs", [])

                # Filter by domain
                domain_lower = domain.lower()
                matches = []
                for p in programs:
                    name = (p.get("name") or "").lower()
                    if domain_lower in name:
                        matches.append(
                            {
                                "name": p.get("name"),
                                "handle": p.get("code"),
                                "url": f"https://bugcrowd.com/{p.get('code')}",
                                "offers_bounties": p.get("max_payout", 0) > 0,
                                "state": "open"
                                if p.get("participation") == "open"
                                else "private",
                            }
                        )

                return matches[:10]

            return []

    except Exception as exc:
        logger.debug("Bugcrowd search failed for {}: {}", domain, exc)
        return []


# ---------------------------------------------------------------------------
# Scope Analysis
# ---------------------------------------------------------------------------


async def check_target_scope(domain: str) -> dict[str, Any]:
    """Check if a domain is in any bug bounty program.

    Queries HackerOne and Bugcrowd for matching programs.

    Args:
        domain: Target domain to check (e.g. "example.com")

    Returns:
        Dict with scope information
    """
    result: dict[str, Any] = {
        "domain": domain,
        "in_scope": False,
        "programs": [],
        "platforms_checked": ["hackerone", "bugcrowd"],
        "severity_levels": [],
        "bounty_available": False,
    }

    # Search both platforms in parallel
    import asyncio

    h1_task = asyncio.create_task(search_hackerone_programs(domain))
    bc_task = asyncio.create_task(search_bugcrowd_programs(domain))

    h1_results, bc_results = await asyncio.gather(
        h1_task, bc_task, return_exceptions=True
    )

    all_programs: list[dict] = []

    if isinstance(h1_results, list):
        for p in h1_results:
            p["platform"] = "hackerone"
            all_programs.append(p)

    if isinstance(bc_results, list):
        for p in bc_results:
            p["platform"] = "bugcrowd"
            all_programs.append(p)

    # Get detailed scope for HackerOne programs
    detailed_programs: list[dict] = []
    for p in all_programs:
        if p.get("platform") == "hackerone" and p.get("handle"):
            detail = await query_hackerone(p["handle"])
            if detail:
                p["detail"] = detail
                # Check if domain is in scope
                scopes = detail.get("structured_scope_versions", {}).get("edges", [])
                for scope_edge in scopes:
                    scope = scope_edge.get("node", {})
                    asset = scope.get("asset_identifier", "")
                    if domain in asset or asset == "*":
                        p["domain_in_scope"] = True
                        p["max_severity"] = scope.get("max_severity", "unknown")
                        p["eligible_for_bounty"] = scope.get(
                            "eligible_for_bounty", False
                        )

        detailed_programs.append(p)

    if detailed_programs:
        result["in_scope"] = True
        result["programs"] = detailed_programs
        result["bounty_available"] = any(
            p.get("offers_bounties") or p.get("eligible_for_bounty")
            for p in detailed_programs
        )

        # Collect severity levels
        severities = set()
        for p in detailed_programs:
            if p.get("max_severity"):
                severities.add(p["max_severity"])
        result["severity_levels"] = sorted(severities)

    return result


async def check_target_multi(targets: list[str]) -> list[dict]:
    """Check scope for multiple targets.

    Args:
        targets: List of domains to check

    Returns:
        List of scope results
    """
    import asyncio

    sem = asyncio.Semaphore(5)  # Limit concurrent queries

    async def _check_one(domain: str) -> dict:
        async with sem:
            return await check_target_scope(domain)

    results = await asyncio.gather(
        *[_check_one(t) for t in targets],
        return_exceptions=True,
    )

    return [r for r in results if isinstance(r, dict)]
