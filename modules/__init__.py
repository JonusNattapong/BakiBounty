"""
BakiBounty - Modules Package

Each module implements one phase of the pipeline:
  - recon       : Passive/active subdomain enumeration
  - probing     : HTTP probing & technology detection
  - discovery   : Content & endpoint discovery
  - scanner     : Vulnerability scanning
  - scope       : Bug bounty program scope checker
"""

from modules.bounty import run_bounty_search
from modules.discovery import run_discovery, run_katana
from modules.probing import run_httpx, run_probing
from modules.recon import run_amass, run_recon, run_subfinder
from modules.scanner import run_ffuf, run_nuclei, run_scanner
from modules.scope import check_target_multi, check_target_scope

__all__ = [
    "check_target_multi",
    "check_target_scope",
    "run_amass",
    "run_bounty_search",
    "run_discovery",
    "run_ffuf",
    "run_httpx",
    "run_katana",
    "run_nuclei",
    "run_probing",
    "run_recon",
    "run_scanner",
    "run_subfinder",
]
