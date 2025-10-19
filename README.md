# Ante Advanced Reconnaissance System

A flexible reconnaissance tool that works with or without API keys. Performs comprehensive domain analysis including subdomain discovery, vulnerability scanning, and intelligence gathering.

## Features

### Basic Mode (No API Keys)
- Certificate transparency scanning
- DNS enumeration with common subdomains
- Live host detection and enhanced port scanning
- **Smap passive scanning** (200 hosts/sec, no target contact)
- SSL certificate and technology analysis
- Vulnerability scanning with Nuclei
- Cloud infrastructure detection
- Social intelligence (Reddit, Wayback Machine)
- Configuration exposure detection

### Full Mode (With Free APIs)
- All Basic Mode features
- Enhanced subdomain discovery via APIs
- GitHub/GitLab sensitive data searches
- VirusTotal threat intelligence
- Microsoft/Office365 enumeration
- Cloud storage discovery (S3, Azure, GCS)
- **Advanced Smap integration** with vulnerability intelligence
- Advanced threat correlation

## Requirements

**Essential:** dig, whois, nmap, curl, jq, openssl, python3

**Optional:** subfinder, httpx, nuclei, naabu, subzy

Install Go tools:
```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

## API Setup (Free)

**GitHub** (recommended): https://github.com/settings/tokens
- Scopes: `public_repo`, `read:user`
- `export GITHUB_TOKEN="your_token"`

**VirusTotal** (recommended): https://www.virustotal.com/gui/join-us  
- `export VIRUSTOTAL_API_KEY="your_key"`

**Chaos** (optional): https://chaos.projectdiscovery.io/
- `export CHAOS_API_KEY="your_key"`

## Output

Creates timestamped directory:
```
ante_recon_domain.com_20240922_143022/
├── summary/           # Executive reports
├── subdomains/        # Discovered subdomains  
├── live_hosts/        # Active services
├── vulns/             # Vulnerabilities
├── cloud_recon/       # Cloud infrastructure
├── osint/             # Social intelligence
└── config_analysis/   # Configuration issues
```

## 15 Reconnaissance Phases

1. ASN Discovery
2. Enhanced Subdomain Enumeration  
3. Live Host Discovery
4. Subdomain Takeover Detection
5. Port Scanning
6. SSL Analysis
7. Cloud Infrastructure Analysis
8. Technology Detection
9. Vulnerability Scanning
10. VirusTotal Intelligence (Full mode)
11. GitHub Intelligence (Full mode)
12. Microsoft Services (Full mode)
13. OSINT Intelligence
14. Configuration Analysis
15. Report Generation

## Key Features

- **Auto-detection**: Switches between Basic/Full based on available APIs
- **Intelligence**: Social media, historical analysis, cloud storage discovery
- **Professional reports**: Executive summaries and investigation checklists
- **Threat intelligence**: VirusTotal integration for reputation analysis
- **Flexible**: Works with or without API keys
- **Respectful**: Rate limiting and error handling

## Commands

```bash
./ante.sh domain.com                 # Auto-detect mode
./ante.sh domain.com --no-apis       # Force basic mode
./ante.sh domain.com --skip-cloud    # Skip cloud scanning
./ante.sh domain.com --api-mode      # Interactive setup
```


## Legal Use Only

- Only test domains you own or have permission to test
- Verify findings manually
- Follow responsible disclosure
- Respect API terms of service

## Credits

**Tools**: ProjectDiscovery (subfinder, httpx, nuclei, naabu), s0md3v (smap), PentestPad (subzy)
**APIs**: GitHub, VirusTotal, Chaos, Certificate Transparency
**Author**: @jLaHire (2025)