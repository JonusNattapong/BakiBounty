"""
BakiBounty - Report Generator

Generates structured reports from collected JSON results:
- Markdown: Clean, readable, GitHub-compatible
- HTML: Styled, self-contained, shareable

Reads all phase JSONs from a run directory and aggregates into
a comprehensive security assessment report.
"""

from __future__ import annotations

import html as html_mod
from datetime import datetime
from pathlib import Path

from loguru import logger

from utils.helpers import load_json

# ---------------------------------------------------------------------------
# Data Aggregation
# ---------------------------------------------------------------------------


class RunData:
    """Aggregated data from a scan run directory."""

    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self.target: str = (
            run_dir.name.rsplit("_", 2)[0] if "_" in run_dir.name else run_dir.name
        )
        self.timestamp: str = ""

        # Phase data
        self.subdomains: list[dict] = []
        self.alive_hosts: list[dict] = []
        self.endpoints: list[dict] = []
        self.findings: list[dict] = []
        self.ffuf_results: list[dict] = []

        # Stats
        self.phase_durations: dict[str, float] = {}
        self.severity_counts: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        self.tech_stack: dict[str, int] = {}
        self.status_distribution: dict[int, int] = {}

        self._load()

    def _load(self) -> None:
        """Load all JSON result files from the run directory."""
        if not self.run_dir.is_dir():
            logger.error("Run directory not found: {}", self.run_dir)
            return

        # Try to get timestamp from directory name
        parts = self.run_dir.name.split("_")
        if len(parts) >= 3:
            try:
                ts = f"{parts[-2]}_{parts[-1]}"
                dt = datetime.strptime(ts, "%Y%m%d_%H%M%S")
                self.timestamp = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            except ValueError:
                self.timestamp = self.run_dir.name

        # Recon
        recon_file = self.run_dir / "recon.json"
        if recon_file.is_file():
            data = load_json(recon_file)
            self.subdomains = data.get("items", [])
            self.phase_durations["recon"] = data.get("duration", 0)

        # Probing
        probe_file = self.run_dir / "probing.json"
        if probe_file.is_file():
            data = load_json(probe_file)
            self.alive_hosts = data.get("items", [])
            self.phase_durations["probe"] = data.get("duration", 0)
            self._aggregate_tech()
            self._aggregate_status()

        # Discovery
        disc_file = self.run_dir / "discovery.json"
        if disc_file.is_file():
            data = load_json(disc_file)
            self.endpoints = data.get("items", [])
            self.phase_durations["discover"] = data.get("duration", 0)

        # Scanner (nuclei)
        scan_file = self.run_dir / "scanner.json"
        if not scan_file.is_file():
            scan_file = self.run_dir / "scan_nuclei.json"
        if scan_file.is_file():
            data = load_json(scan_file)
            self.findings = data.get("items", [])
            self.phase_durations["scan"] = data.get("duration", 0)
            self._aggregate_severity()

        # ffuf
        ffuf_file = self.run_dir / "scan_ffuf.json"
        if ffuf_file.is_file():
            data = load_json(ffuf_file)
            self.ffuf_results = data.get("items", [])
            if "scan" not in self.phase_durations:
                self.phase_durations["scan"] = data.get("duration", 0)

    def _aggregate_tech(self) -> None:
        """Count technologies across alive hosts."""
        for host in self.alive_hosts:
            techs = host.get("tech", [])
            if isinstance(techs, list):
                for t in techs:
                    self.tech_stack[t] = self.tech_stack.get(t, 0) + 1
            elif isinstance(techs, str):
                for t in techs.split(","):
                    t = t.strip()
                    if t:
                        self.tech_stack[t] = self.tech_stack.get(t, 0) + 1

    def _aggregate_severity(self) -> None:
        """Count findings by severity."""
        for finding in self.findings:
            sev = finding.get("severity", "info").lower()
            self.severity_counts[sev] = self.severity_counts.get(sev, 0) + 1

    def _aggregate_status(self) -> None:
        """Count HTTP status codes."""
        for host in self.alive_hosts:
            sc = host.get("status_code", 0)
            self.status_distribution[sc] = self.status_distribution.get(sc, 0) + 1

    @property
    def total_duration(self) -> float:
        return sum(self.phase_durations.values())

    @property
    def top_tech(self) -> list[tuple[str, int]]:
        return sorted(self.tech_stack.items(), key=lambda x: x[1], reverse=True)[:10]

    @property
    def critical_findings(self) -> list[dict]:
        return [f for f in self.findings if f.get("severity") == "critical"]

    @property
    def high_findings(self) -> list[dict]:
        return [f for f in self.findings if f.get("severity") == "high"]


# ---------------------------------------------------------------------------
# Markdown Report
# ---------------------------------------------------------------------------


def generate_markdown(data: RunData) -> str:
    """Generate a Markdown report from run data."""
    lines: list[str] = []

    # Header
    lines.append(f"# BakiBounty Report: {data.target}")
    lines.append("")
    if data.timestamp:
        lines.append(f"**Generated:** {data.timestamp}  ")
    lines.append(f"**Duration:** {data.total_duration:.1f}s  ")
    lines.append("")

    # Summary
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
    lines.append(f"| Subdomains | {len(data.subdomains)} |")
    lines.append(f"| Alive Hosts | {len(data.alive_hosts)} |")
    lines.append(f"| Endpoints | {len(data.endpoints)} |")
    lines.append(f"| Findings | {len(data.findings)} |")
    lines.append(f"| Fuzzed Paths | {len(data.ffuf_results)} |")
    lines.append("")

    # Severity breakdown
    if any(v > 0 for v in data.severity_counts.values()):
        lines.append("### Findings by Severity")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = data.severity_counts.get(sev, 0)
            if count > 0:
                icon = {
                    "critical": "!!",
                    "high": "!",
                    "medium": "~",
                    "low": "-",
                    "info": "i",
                }.get(sev, "")
                lines.append(f"| {icon} {sev.upper()} | {count} |")
        lines.append("")

    # Phase timings
    lines.append("### Phase Timings")
    lines.append("")
    lines.append("| Phase | Duration |")
    lines.append("|-------|----------|")
    for phase, dur in data.phase_durations.items():
        lines.append(f"| {phase} | {dur:.1f}s |")
    lines.append(f"| **Total** | **{data.total_duration:.1f}s** |")
    lines.append("")

    # Critical findings (full detail)
    if data.critical_findings:
        lines.append("## CRITICAL FINDINGS")
        lines.append("")
        for f in data.critical_findings:
            lines.append(f"### {f.get('name', f.get('template', 'Unknown'))}")
            lines.append("")
            lines.append(f"- **Template:** `{f.get('template', '')}`")
            lines.append(f"- **Host:** {f.get('host', '')}")
            lines.append(f"- **Matched At:** {f.get('matched_at', '')}")
            if f.get("cve"):
                lines.append(f"- **CVE:** {f.get('cve', '')}")
            if f.get("cvss"):
                lines.append(f"- **CVSS:** {f.get('cvss', '')}")
            if f.get("description"):
                lines.append(f"- **Description:** {f.get('description', '')}")
            if f.get("evidence"):
                lines.append(f"- **Evidence:** `{f.get('evidence', '')}`")
            if f.get("references"):
                refs = f["references"]
                if isinstance(refs, list):
                    for ref in refs:
                        lines.append(f"- **Ref:** {ref}")
            lines.append("")

    # High findings
    if data.high_findings:
        lines.append("## HIGH FINDINGS")
        lines.append("")
        lines.append("| Template | Host | Matched At |")
        lines.append("|----------|------|------------|")
        for f in data.high_findings:
            name = f.get("name", f.get("template", ""))
            host = f.get("host", "")
            matched = f.get("matched_at", "")
            lines.append(f"| {name} | {host} | {matched} |")
        lines.append("")

    # Medium/Low findings summary
    medium_low = [f for f in data.findings if f.get("severity") in ("medium", "low")]
    if medium_low:
        lines.append("## MEDIUM/LOW FINDINGS")
        lines.append("")
        lines.append("| Severity | Template | Host |")
        lines.append("|----------|----------|------|")
        for f in medium_low[:50]:  # Cap at 50 to avoid huge reports
            sev = f.get("severity", "").upper()
            name = f.get("name", f.get("template", ""))
            host = f.get("host", "")
            lines.append(f"| {sev} | {name} | {host} |")
        if len(medium_low) > 50:
            lines.append(f"| ... | *{len(medium_low) - 50} more* | |")
        lines.append("")

    # Technology stack
    if data.top_tech:
        lines.append("## Technology Stack")
        lines.append("")
        lines.append("| Technology | Occurrences |")
        lines.append("|------------|-------------|")
        for tech, count in data.top_tech:
            lines.append(f"| {tech} | {count} |")
        lines.append("")

    # Alive hosts sample
    if data.alive_hosts:
        lines.append("## Alive Hosts (sample)")
        lines.append("")
        lines.append("| URL | Status | Title | Tech |")
        lines.append("|-----|--------|-------|------|")
        for host in data.alive_hosts[:30]:
            url = host.get("url", "")
            sc = host.get("status_code", "")
            title = host.get("title", "")[:60]
            techs = host.get("tech", [])
            tech_str = (
                ", ".join(techs[:3]) if isinstance(techs, list) else str(techs)[:40]
            )
            lines.append(f"| {url} | {sc} | {title} | {tech_str} |")
        if len(data.alive_hosts) > 30:
            lines.append(f"| ... | | *{len(data.alive_hosts) - 30} more* | |")
        lines.append("")

    # ffuf results
    if data.ffuf_results:
        lines.append("## Fuzzed Paths (sample)")
        lines.append("")
        lines.append("| URL | Status | Size |")
        lines.append("|-----|--------|------|")
        for r in data.ffuf_results[:30]:
            url = r.get("url", "")
            sc = r.get("status_code", "")
            size = r.get("content_length", "")
            lines.append(f"| {url} | {sc} | {size} |")
        if len(data.ffuf_results) > 30:
            lines.append(f"| ... | | *{len(data.ffuf_results) - 30} more* |")
        lines.append("")

    # Subdomains
    if data.subdomains:
        lines.append("## Discovered Subdomains")
        lines.append("")
        lines.append(f"Total: **{len(data.subdomains)}**")
        lines.append("")
        lines.append("```")
        hosts = sorted(set(s.get("host", "") for s in data.subdomains if s.get("host")))
        for h in hosts[:200]:
            lines.append(h)
        if len(hosts) > 200:
            lines.append(f"... ({len(hosts) - 200} more)")
        lines.append("```")
        lines.append("")

    # Footer
    lines.append("---")
    lines.append("*Generated by BakiBounty*")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML Report
# ---------------------------------------------------------------------------


def generate_html(data: RunData) -> str:
    """Generate a self-contained HTML report from run data."""
    esc = html_mod.escape

    parts: list[str] = []

    # CSS
    css = """
    <style>
      * { margin: 0; padding: 0; box-sizing: border-box; }
      body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
             background: #0d1117; color: #c9d1d9; line-height: 1.6; padding: 2rem; }
      .container { max-width: 1200px; margin: 0 auto; }
      h1 { color: #58a6ff; margin-bottom: 0.5rem; font-size: 2rem; }
      h2 { color: #58a6ff; margin: 2rem 0 1rem; border-bottom: 1px solid #21262d; padding-bottom: 0.5rem; }
      h3 { color: #f0883e; margin: 1.5rem 0 0.5rem; }
      .meta { color: #8b949e; margin-bottom: 2rem; }
      .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                      gap: 1rem; margin: 1rem 0; }
      .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.2rem; }
      .card-value { font-size: 2rem; font-weight: bold; color: #58a6ff; }
      .card-label { color: #8b949e; font-size: 0.9rem; }
      table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
      th { background: #161b22; color: #58a6ff; text-align: left; padding: 0.6rem 1rem;
           border-bottom: 2px solid #30363d; }
      td { padding: 0.5rem 1rem; border-bottom: 1px solid #21262d; }
      tr:hover td { background: #161b22; }
      .sev-critical { color: #f85149; font-weight: bold; }
      .sev-high { color: #f0883e; font-weight: bold; }
      .sev-medium { color: #d29922; }
      .sev-low { color: #8b949e; }
      .sev-info { color: #484f58; }
      code { background: #161b22; padding: 0.2rem 0.4rem; border-radius: 4px; font-size: 0.9em; }
      .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 12px;
               font-size: 0.8rem; font-weight: 600; }
      .badge-critical { background: #f8514920; color: #f85149; border: 1px solid #f85149; }
      .badge-high { background: #f0883e20; color: #f0883e; border: 1px solid #f0883e; }
      .badge-medium { background: #d2992220; color: #d29922; border: 1px solid #d29922; }
      .badge-low { background: #8b949e20; color: #8b949e; border: 1px solid #8b949e; }
      pre { background: #161b22; padding: 1rem; border-radius: 8px; overflow-x: auto;
            border: 1px solid #30363d; max-height: 400px; }
      .footer { margin-top: 3rem; color: #484f58; text-align: center; font-size: 0.85rem; }
      a { color: #58a6ff; text-decoration: none; }
      a:hover { text-decoration: underline; }
    </style>
    """

    parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>BakiBounty Report: {esc(data.target)}</title>
  {css}
</head>
<body>
<div class="container">
""")

    # Header
    parts.append(f"<h1>BakiBounty Report: {esc(data.target)}</h1>")
    parts.append('<p class="meta">')
    if data.timestamp:
        parts.append(f"Generated: {esc(data.timestamp)} &bull; ")
    parts.append(f"Duration: {data.total_duration:.1f}s")
    parts.append("</p>")

    # Summary cards
    parts.append('<div class="summary-grid">')
    cards = [
        (len(data.subdomains), "Subdomains"),
        (len(data.alive_hosts), "Alive Hosts"),
        (len(data.endpoints), "Endpoints"),
        (len(data.findings), "Findings"),
        (len(data.ffuf_results), "Fuzzed Paths"),
    ]
    for value, label in cards:
        parts.append(f'<div class="card"><div class="card-value">{value}</div>')
        parts.append(f'<div class="card-label">{label}</div></div>')
    parts.append("</div>")

    # Severity breakdown
    if any(v > 0 for v in data.severity_counts.values()):
        parts.append("<h2>Findings by Severity</h2>")
        parts.append('<div class="summary-grid">')
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = data.severity_counts.get(sev, 0)
            if count > 0:
                parts.append(
                    f'<div class="card"><div class="card-value sev-{sev}">{count}</div>'
                )
                parts.append(f'<div class="card-label">{sev.upper()}</div></div>')
        parts.append("</div>")

    # Critical findings
    if data.critical_findings:
        parts.append("<h2>CRITICAL FINDINGS</h2>")
        for f in data.critical_findings:
            name = esc(f.get("name", f.get("template", "Unknown")))
            parts.append(f"<h3>{name}</h3>")
            parts.append("<table>")
            details = [
                ("Template", f.get("template", "")),
                ("Host", f.get("host", "")),
                ("Matched At", f.get("matched_at", "")),
                ("CVE", f.get("cve", "")),
                ("CVSS", f.get("cvss", "")),
                ("Description", f.get("description", "")),
            ]
            for label, val in details:
                if val:
                    parts.append(
                        f"<tr><td><strong>{label}</strong></td><td>{esc(str(val))}</td></tr>"
                    )
            evidence = f.get("evidence")
            if evidence:
                ev_str = (
                    ", ".join(evidence) if isinstance(evidence, list) else str(evidence)
                )
                parts.append(
                    f"<tr><td><strong>Evidence</strong></td><td><code>{esc(ev_str)}</code></td></tr>"
                )
            parts.append("</table>")

    # High findings
    if data.high_findings:
        parts.append("<h2>High Findings</h2>")
        parts.append(
            "<table><tr><th>Template</th><th>Host</th><th>Matched At</th></tr>"
        )
        for f in data.high_findings:
            name = esc(f.get("name", f.get("template", "")))
            host = esc(f.get("host", ""))
            matched = esc(f.get("matched_at", ""))
            parts.append(f"<tr><td>{name}</td><td>{host}</td><td>{matched}</td></tr>")
        parts.append("</table>")

    # Technology stack
    if data.top_tech:
        parts.append("<h2>Technology Stack</h2>")
        parts.append("<table><tr><th>Technology</th><th>Occurrences</th></tr>")
        for tech, count in data.top_tech:
            parts.append(f"<tr><td>{esc(tech)}</td><td>{count}</td></tr>")
        parts.append("</table>")

    # Alive hosts
    if data.alive_hosts:
        parts.append("<h2>Alive Hosts</h2>")
        parts.append(
            "<table><tr><th>URL</th><th>Status</th><th>Title</th><th>Tech</th></tr>"
        )
        for host in data.alive_hosts[:50]:
            url = esc(host.get("url", ""))
            sc = host.get("status_code", "")
            title = esc(host.get("title", "")[:80])
            techs = host.get("tech", [])
            tech_str = esc(
                ", ".join(techs[:5]) if isinstance(techs, list) else str(techs)[:50]
            )
            parts.append(
                f"<tr><td>{url}</td><td>{sc}</td><td>{title}</td><td>{tech_str}</td></tr>"
            )
        if len(data.alive_hosts) > 50:
            parts.append(
                f"<tr><td colspan='4'><em>{len(data.alive_hosts) - 50} more...</em></td></tr>"
            )
        parts.append("</table>")

    # Subdomains
    if data.subdomains:
        parts.append(f"<h2>Discovered Subdomains ({len(data.subdomains)})</h2>")
        hosts = sorted(set(s.get("host", "") for s in data.subdomains if s.get("host")))
        parts.append("<pre>")
        for h in hosts[:200]:
            parts.append(esc(h))
        if len(hosts) > 200:
            parts.append(f"\n... ({len(hosts) - 200} more)")
        parts.append("</pre>")

    # Footer
    parts.append('<p class="footer">Generated by BakiBounty</p>')
    parts.append("</div></body></html>")

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def generate_report(
    run_dir: Path,
    formats: list[str] | None = None,
    output_dir: Path | None = None,
) -> dict[str, Path]:
    """Generate reports in requested formats.

    Args:
        run_dir: Path to run output directory.
        formats: List of formats ("markdown", "html"). Defaults to both.
        output_dir: Where to save reports (defaults to run_dir).

    Returns:
        Dict mapping format name to generated file path.
    """
    if formats is None:
        formats = ["markdown", "html"]
    if output_dir is None:
        output_dir = run_dir

    output_dir.mkdir(parents=True, exist_ok=True)

    data = RunData(run_dir)
    generated: dict[str, Path] = {}

    if "markdown" in formats or "md" in formats:
        md_content = generate_markdown(data)
        md_path = output_dir / "report.md"
        md_path.write_text(md_content, encoding="utf-8")
        generated["markdown"] = md_path
        logger.info("Generated markdown report: {}", md_path)

    if "html" in formats:
        html_content = generate_html(data)
        html_path = output_dir / "report.html"
        html_path.write_text(html_content, encoding="utf-8")
        generated["html"] = html_path
        logger.info("Generated HTML report: {}", html_path)

    return generated
