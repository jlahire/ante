# Ante

A flexible reconnaissance tool that works with or without API keys. Performs comprehensive domain analysis including DNS enumeration, subdomain discovery, port scanning, vulnerability assessment, and threat intelligence gathering.

Named "Ante" after the poker term - you invest resources upfront to see what information is available before making your next move in security assessment.

## Features

### Basic Mode (No API Keys Required)
- Certificate Transparency scanning via crt.sh
- DNS enumeration with common subdomains
- Live host detection with HTTP/HTTPS probing
- Port scanning (top 1000 ports)
- SSL certificate analysis
- Web technology identification
- Vulnerability scanning with Nuclei
- Cloud infrastructure detection
- Professional reporting and analysis

### Full Mode (Enhanced with Free APIs)
- All Basic Mode features PLUS:
- Enhanced subdomain discovery via multiple APIs
- GitHub code search for sensitive data exposure
- VirusTotal threat intelligence and reputation analysis
- Microsoft/Office365 service enumeration
- Advanced threat intelligence correlation
- Subdomain takeover detection
- Comprehensive attack surface mapping

## Quick Start

```bash
# Basic mode (works immediately)
./ante.sh example.com --no-apis

# Full mode (requires API keys)
./ante.sh example.com

# Interactive setup
./ante.sh example.com --api-mode
```

## System Requirements

**Essential Tools (Required):**
- dig, whois, nmap, curl, jq, openssl
- Python 3 with ipaddress module

**Optional Tools (Enhanced Capabilities):**
- subfinder - Enhanced subdomain enumeration
- httpx - Advanced HTTP probing
- nuclei - Vulnerability scanning
- naabu - Fast port scanning
- subzy - Subdomain takeover detection

**Install Go Tools:**
```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/PentestPad/subzy@latest
```

## Command Options

```bash
./ante.sh <domain> [options]

Options:
  --no-apis        Force basic mode without API requirements
  --skip-cloud     Skip cloud infrastructure analysis
  --api-mode       Interactive API key configuration
  --help, -h       Show detailed help information

Examples:
  ./ante.sh tesla.com                    # Auto-detect mode based on APIs
  ./ante.sh tesla.com --no-apis          # Basic reconnaissance only
  ./ante.sh tesla.com --skip-cloud       # Skip cloud provider detection
```

## API Configuration (Optional but Recommended)

All APIs listed are **completely free** with no charges:

### GitHub API Token
- **URL:** https://github.com/settings/tokens
- **Scopes:** `public_repo`, `read:user`
- **Benefits:** GitHub code search, enhanced subdomain discovery
- **Usage:** `export GITHUB_TOKEN="ghp_xxxxxxxxxxxx"`

### Chaos API Key  
- **URL:** https://chaos.projectdiscovery.io/
- **Sign up:** Use GitHub account for easy registration
- **Benefits:** Access to massive subdomain database
- **Usage:** `export CHAOS_API_KEY="your_key_here"`

### URLScan API Key
- **URL:** https://urlscan.io/user/signup  
- **Limit:** 1000 scans/day (free tier)
- **Benefits:** Advanced web analysis and screenshots
- **Usage:** `export URLSCAN_API_KEY="your_key_here"`

### VirusTotal API Key
- **URL:** https://www.virustotal.com/gui/join-us
- **Limit:** 500 requests/day, 4 requests/minute (free tier)
- **Benefits:** Threat intelligence, domain reputation, malware detection
- **Usage:** `export VIRUSTOTAL_API_KEY="your_key_here"`

## Output Structure

The tool creates a timestamped directory with organized results:

```
ante_recon_domain.com_20240922_143022/
├── asn/                    # ASN and IP range information
├── subdomains/             # All discovered subdomains
├── live_hosts/             # Active web services
├── portscan/               # Open ports and services
├── ssl/                    # SSL certificate analysis
├── tech_stack/             # Web technologies identified
├── vulns/                  # Vulnerability scan results
├── cloud_recon/            # Cloud provider analysis
├── virustotal/             # Threat intelligence reports (full mode)
├── github/                 # GitHub search results (full mode)
├── microsoft/              # Office365/Azure services (full mode)
└── summary/                # Executive reports and checklists
    ├── reconnaissance_report.md
    ├── investigation_checklist.md
    └── high_value_targets.txt
```

## Reconnaissance Phases

1. **ASN Discovery** - IP ranges and autonomous systems
2. **Subdomain Enumeration** - Certificate transparency + DNS + APIs
3. **Live Host Discovery** - HTTP/HTTPS service detection
4. **Subdomain Takeover** - Vulnerability assessment
5. **Port Scanning** - Network service enumeration
6. **SSL Analysis** - Certificate examination
7. **Cloud Infrastructure** - Provider identification
8. **Technology Detection** - Web stack identification
9. **Vulnerability Scanning** - Nuclei template execution
10. **VirusTotal Intelligence** - Threat analysis and reputation (full mode)
11. **GitHub Intelligence** - Sensitive data search (full mode)
12. **Microsoft Services** - Office365/Azure enumeration (full mode)
13. **Report Generation** - Comprehensive analysis

## Key Features

- **Mode Auto-Detection:** Automatically switches between Basic/Full modes based on available APIs
- **Professional Reporting:** Executive summaries, investigation checklists, and detailed findings
- **Threat Intelligence:** VirusTotal integration for reputation analysis and threat detection
- **Comprehensive Coverage:** Network, web application, and cloud infrastructure assessment  
- **Flexible Operation:** Works effectively with or without API keys
- **Rate Limiting:** Respectful of API limits and target systems
- **Error Handling:** Graceful degradation when tools are unavailable
- **Progress Tracking:** Clear phase-by-phase execution with colored output

## Validation and Management

```bash
# Validate system status
~/ante_recon/validate_system.sh

# Setup API keys interactively  
~/ante_recon/setup_apis.sh

# Update cloud IP ranges
~/ante_recon/update_ranges.sh
```

## VirusTotal Integration Features

**Domain Analysis:**
- Reputation scoring and categorization
- Historical analysis data
- Community voting results
- Malicious/suspicious indicators

**IP Analysis:**
- Geographic location and ASN information
- Reputation scoring
- Threat classification
- Historical security events

**Automated Flagging:**
- Identifies potentially malicious domains/IPs
- Creates prioritized threat reports
- Generates actionable intelligence
- Correlates findings across assets

## Legal and Ethical Use

**IMPORTANT:** This tool is for authorized security testing only.

- Only test domains you own or have explicit written permission to assess
- Verify all findings manually before taking action
- Some automated results may be false positives  
- Follow responsible disclosure for any vulnerabilities discovered
- Respect rate limits and target system resources
- VirusTotal data should be used for defensive purposes only

## Troubleshooting

**Common Issues:**

1. **Missing Tools:** Install Go tools listed in requirements
2. **API Limits:** Reduce scan scope or implement delays
3. **Permission Denied:** Ensure script has execute permissions
4. **Network Issues:** Check connectivity and DNS resolution
5. **VirusTotal Rate Limits:** Free tier has 4 requests/minute limit

**Getting Help:**

```bash
# System validation
./validate_system.sh

# Detailed help
./ante.sh --help

# Check tool availability
which subfinder httpx nuclei naabu
```

## Credits and Acknowledgments

### Tool Dependencies

This reconnaissance system integrates and depends on several open-source security tools:

**Core Go Tools:**
- **[Subfinder](https://github.com/projectdiscovery/subfinder)** - Subdomain discovery by ProjectDiscovery
- **[Httpx](https://github.com/projectdiscovery/httpx)** - Fast HTTP probe by ProjectDiscovery
- **[Nuclei](https://github.com/projectdiscovery/nuclei)** - Vulnerability scanner by ProjectDiscovery
- **[Naabu](https://github.com/projectdiscovery/naabu)** - Fast port scanner by ProjectDiscovery
- **[Katana](https://github.com/projectdiscovery/katana)** - Web crawler by ProjectDiscovery
- **[Subzy](https://github.com/PentestPad/subzy)** - Subdomain takeover detection by PentestPad

**System Tools:**
- **dig** - DNS lookup utility (BIND utilities)
- **whois** - Domain registration lookup
- **nmap** - Network discovery and security auditing by Nmap Project
- **curl** - Command line HTTP client
- **jq** - JSON processor
- **openssl** - SSL/TLS toolkit

**External APIs:**
- **[VirusTotal API](https://www.virustotal.com/)** - Threat intelligence platform
- **[GitHub API](https://docs.github.com/en/rest)** - Code repository search
- **[Chaos API](https://chaos.projectdiscovery.io/)** - Subdomain database by ProjectDiscovery
- **[URLScan API](https://urlscan.io/)** - Website analysis service
- **[Certificate Transparency (crt.sh)](https://crt.sh/)** - SSL certificate logs

**Data Sources:**
- **[SecLists](https://github.com/danielmiessler/SecLists)** - Security wordlists by Daniel Miessler
- **[AWS IP Ranges](https://ip-ranges.amazonaws.com/)** - Amazon Web Services
- **[GCP IP Ranges](https://www.gstatic.com/ipranges/)** - Google Cloud Platform
- **[Cloudflare IP Ranges](https://www.cloudflare.com/ips/)** - Cloudflare CDN

### Development

- **Author:** @jLaHire (2025)
- **Built with AI assistance** from Anthropic's Claude
- **Inspired by:** The security research community and penetration testing methodologies
- **Designed for:** Practical reconnaissance workflows and security assessment automation

### Community Contributions

Special thanks to:
- **[ProjectDiscovery Team](https://github.com/projectdiscovery)** - For creating excellent open-source security tools
- **[PentestPad](https://github.com/PentestPad)** - For subdomain takeover detection capabilities  
- **Security Research Community** - For vulnerability templates and methodologies
- **Open Source Contributors** - For maintaining the tools this system depends on

### Responsible Use

This tool builds upon the work of many security researchers and developers. Please:
- Respect the licenses and terms of service of all integrated tools and APIs
- Use only for authorized security testing and research
- Contribute back to the open-source security community when possible
- Follow responsible disclosure practices for any vulnerabilities discovered

## License

This tool is provided for educational and authorized security testing purposes. Users are responsible for compliance with all applicable laws and regulations. All integrated tools retain their original licenses and terms of use.Office365 service enumeration
- Advanced threat intelligence correlation
- Subdomain takeover detection
- Comprehensive attack surface mapping
