# Ante Reconnaissance Script

A reconnaissance tool that works with or without API keys. Does DNS enumeration, subdomain discovery, port scanning, vulnerability checks, and more.

Named "Ante" after the poker term - you put something up front before seeing what cards you get. Same idea with recon - you invest time upfront to see what's actually there before making your next move.

## Quick Start

```bash
# Basic mode (no APIs needed)
./ante.sh example.com --no-apis

# Full mode (with API keys)
export GITHUB_TOKEN="your_token_here"
export CHAOS_API_KEY="your_key_here"
./ante.sh example.com
```

## What It Does

- Finds subdomains and live hosts
- Scans ports and identifies services
- Checks for vulnerabilities with Nuclei
- Analyzes SSL certificates
- Searches GitHub for exposed secrets (full mode)
- Generates reports and checklists

## Requirements

**Essential:**

- dig, whois, nmap, curl, jq

**Optional (for better results):**

- subfinder, httpx, nuclei, naabu

Install the Go tools:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

## Options

- `--no-apis` - Run without API keys (basic mode)
- `--skip-cloud` - Skip cloud infrastructure checks
- `--api-mode` - Interactive API setup

## API Keys (Optional)

For enhanced subdomain discovery:

- [GitHub](https://github.com/settings/tokens)
- [Chaos](https://chaos.projectdiscovery.io/)
- [URLScan](https://urlscan.io/user/signup)

## Output

Creates a timestamped directory with:

- Detailed markdown report
- Investigation checklist  
- Raw scan results
- High-value targets list

## Legal Notice

Only use on domains you own or have permission to test. This is for authorized security testing only.

## Credits

Created by @jLaHire with AI assistance. Built for practical reconnaissance work.
