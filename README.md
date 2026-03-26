# BakiBounty

Advanced bug bounty automation framework for reconnaissance, probing, content discovery, and vulnerability scanning.

## Features

- **Async-first pipeline** — all modules run async for maximum speed
- **Parallel multi-target** — scan multiple targets concurrently with `-j`
- **Modular architecture** — easy to add new tools/modules
- **Rich console output** — progress tables, colored results
- **Auto-reporting** — Markdown and HTML reports from scan results
- **Notifications** — Telegram/Discord alerts on critical/high findings
- **Config validation** — Pydantic v2 validates all settings

## Pipeline

```
recon (subfinder/amass) → probe (httpx) → discover (katana) → scan (nuclei/ffuf) → report
```

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Check tool availability
python main.py doctor

# Run full pipeline
python main.py run example.com

# Parallel scan (3 targets at once)
python main.py run targets.txt -j 3

# Run specific modules
python main.py recon subfinder example.com
python main.py probe httpx hosts.txt
python main.py discover katana urls.txt
python main.py scan nuclei targets.txt
python main.py scan ffuf https://example.com/FUZZ

# Generate report from existing results
python main.py report output/run_dir/

# Test notifications
python main.py notify -m "Test alert"
```

## Configuration

Edit `config/config.yaml` or create your own:

```bash
python main.py run example.com -c myconfig.yaml
```

### Key Settings

```yaml
general:
  threads: 20           # Concurrent threads per tool
  rate_limit: 150       # Requests per second
  timeout: 30           # Per-tool timeout (seconds)

recon:
  sources: [subfinder]  # subfinder, amass

scanning:
  nuclei:
    severity: [critical, high, medium]
    concurrency: 25
  ffuf:
    wordlist: /usr/share/seclists/Discovery/Web-Content/common.txt
    extensions: [.php, .asp, .aspx, .jsp, .html]

notifications:
  enabled: true
  telegram:
    bot_token: "123456:ABC..."
    chat_id: "-100..."
  discord:
    webhook_url: "https://discord.com/api/webhooks/..."
  on: [critical, high]
```

## Output

Results are saved to `output/<target>_<timestamp>/`:

```
output/example.com_20260326_120000/
├── recon.json            # All discovered subdomains
├── recon_subfinder.json  # Subfinder raw results
├── subdomains.txt        # Flat subdomain list
├── probing.json          # Alive hosts with metadata
├── alive_urls.txt        # Alive URL list
├── discovery.json        # Discovered endpoints
├── endpoints.txt         # Unique endpoints
├── scanner.json          # All findings merged
├── scan_nuclei.json      # Nuclei raw results
├── scan_ffuf.json        # ffuf raw results
├── report.md             # Markdown report
└── report.html           # HTML report
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `run <target>` | Full pipeline |
| `run <target> -j N` | Parallel N targets |
| `run <target> --skip-recon` | Skip recon phase |
| `run <target> --skip-scan` | Skip scanning phase |
| `recon subfinder <target>` | Passive subdomain enum |
| `recon amass <target>` | Deep enumeration |
| `probe httpx <hosts>` | HTTP probing |
| `discover katana <urls>` | Content discovery |
| `scan nuclei <targets>` | Vulnerability scanning |
| `scan ffuf <url>` | Content fuzzing |
| `report <dir>` | Generate reports |
| `doctor` | Check tool availability |
| `notify` | Test notification channels |

## Project Structure

```
main.py              # CLI entry (typer + rich)
config/
  config.yaml        # Default configuration
  schema.py          # Pydantic v2 models
modules/
  recon.py           # subfinder + amass
  probing.py         # httpx wrapper
  discovery.py       # katana wrapper
  scanner.py         # nuclei + ffuf
utils/
  helpers.py         # Tool resolver, subprocess, JSON I/O
  logger.py          # loguru + rich logging
  notify.py          # Telegram/Discord notifications
  report.py          # Markdown/HTML report generator
output/              # Timestamped run results
templates/           # Custom nuclei templates
```

## Requirements

- Python 3.11+
- External tools (install separately):
  - [subfinder](https://github.com/projectdiscovery/subfinder)
  - [httpx](https://github.com/projectdiscovery/httpx)
  - [nuclei](https://github.com/projectdiscovery/nuclei)
  - [katana](https://github.com/projectdiscovery/katana)
  - [ffuf](https://github.com/ffuf/ffuf)
  - [amass](https://github.com/owasp-amass/amass) (optional)

## License

MIT
