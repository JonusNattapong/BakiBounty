from __future__ import annotations

import asyncio
import time
from typing import Any, Optional

import httpx
from loguru import logger

from utils.helpers import ModuleResult


async def fetch_programs(source: str, data_url: str) -> list[dict]:
    """Fetch bounty program data from a specific source (GitHub aggregator)."""
    url = f"{data_url.rstrip('/')}/{source}_data.json"
    logger.debug("Fetching {} data from {}", source, url)
    try:
        async with httpx.AsyncClient(timeout=60, follow_redirects=True) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            return resp.json()
    except Exception as exc:
        logger.error("Failed to fetch {} data: {}", source, exc)
        return []


def extract_domains(program: dict) -> list[str]:
    """Extract domains and wildcards from a program's in-scope targets."""
    domains = set()
    targets = program.get("targets", {}).get("in_scope", [])

    for target in targets:
        # HackerOne fields: asset_identifier, asset_type
        # Bugcrowd fields: target, type
        # Intigriti fields: endpoint, type

        identifier = (
            target.get("asset_identifier")
            or target.get("target")
            or target.get("endpoint")
        )
        asset_type = (target.get("asset_type") or target.get("type") or "").lower()

        if not identifier:
            continue

        # Standardize wildcards and domains
        if asset_type in ("url", "wildcard", "domain", "host", "website"):
            # Clean up common prefixes
            clean = (
                identifier.replace("http://", "")
                .replace("https://", "")
                .split("/")[0]
            )
            if "." in clean:
                domains.add(clean)
        elif "." in identifier and not any(x in identifier for x in (":", "/", " ")):
            # Heuristic for accidental domains
            domains.add(identifier)

    return sorted(list(domains))


async def run_bounty_search(
    query: str,
    cfg: Any,
    *,
    bounty_only: bool = False,
    limit: int = 100,
) -> ModuleResult:
    """Search for bug bounty programs matching a query and extract their domains.

    Args:
        query: Search keyword for program name or handle
        cfg: BakiConfig object
        bounty_only: If True, only include programs that offer monetary rewards
        limit: Max number of domains across all matched programs
    """
    start = time.monotonic()

    all_domains = set()
    errors = []
    found_programs = []

    sources = cfg.bounty.sources
    data_url = cfg.bounty.data_url

    logger.info("Searching for bounty programs matching '{}' across {} sources...", query, len(sources))

    tasks = [fetch_programs(s, data_url) for s in sources]
    results = await asyncio.gather(*tasks)

    query_lower = query.lower()

    for source_idx, programs in enumerate(results):
        source_name = sources[source_idx]
        if not programs:
            errors.append(f"No programs loaded for source: {source_name}")
            continue

        source_count = 0
        for program in programs:
            name = (program.get("name") or "").lower()
            handle = (program.get("handle") or "").lower()

            # Filter by query
            if query_lower not in name and query_lower not in handle:
                continue

            # Filter by bounty
            if bounty_only:
                offers_bounty = program.get("offers_bounties") or (program.get("max_payout") or 0) > 0
                if not offers_bounty:
                    continue

            prog_domains = extract_domains(program)
            if prog_domains:
                # Add up to limit
                new_domains = [d for d in prog_domains if d not in all_domains]
                if len(all_domains) + len(new_domains) > limit:
                    remaining_slots = limit - len(all_domains)
                    new_domains = new_domains[:remaining_slots]

                if new_domains:
                    all_domains.update(new_domains)
                    found_programs.append(
                        {
                            "name": program.get("name"),
                            "handle": program.get("handle"),
                            "url": program.get("url"),
                            "source": source_name,
                            "offers_bounty": program.get("offers_bounties", False),
                            "max_payout": program.get("max_payout"),
                            "domains": prog_domains, # original domains list
                            "added_count": len(new_domains),
                        }
                    )
                    source_count += 1
                
                if len(all_domains) >= limit:
                    break

        if source_count > 0:
            logger.debug("Found {} programs in {}", source_count, source_name)
        
        if len(all_domains) >= limit:
            logger.info("Reached domain limit ({})", limit)
            break

    status = "success" if all_domains else "failed"
    if not all_domains and not errors:
        errors.append(f"No bug bounty programs found matching '{query}'")

    return ModuleResult(
        module="bounty",
        target=query,
        status=status,
        items=found_programs,
        item_count=len(all_domains),
        errors=errors,
        duration=round(time.monotonic() - start, 3),
    )
