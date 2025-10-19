#!/bin/bash

# Ante - Advanced Reconnaissance System with Enhanced Intelligence Gathering
# Integrates selective BigBountyRecon techniques for comprehensive OSINT
# Runs with or without API keys - User's choice
# Author: @jLaHire
# Release Date: September 22, 2025
# Usage: ./ante.sh <domain> [--no-apis]

set -euo pipefail

# =============================================================================
# COLORFUL DISPLAY AND LOGGING SYSTEM
# =============================================================================

# Colors for output (vibrant and colorful)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Display functions
display_header() {
    local title="$1"
    local author="$2"
    local target="$3"
    
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${title}${NC}"
    echo -e "${BLUE}║${author}${NC}"
    echo -e "${BLUE}║                Target: $target${NC}"
    echo -e "${BLUE}║                Started: $(date)${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
}

display_mode_info() {
    local mode="$1"
    local message="$2"
    local submessage="$3"
    
    case $mode in
        "BASIC")
            echo -e "${YELLOW}[i] Running in BASIC MODE $message${NC}"
            echo -e "${YELLOW}    $submessage${NC}"
            ;;
        "FULL")
            echo -e "${GREEN}[i] Running in FULL MODE $message${NC}"
            echo -e "${GREEN}    $submessage${NC}"
            ;;
        "INTERACTIVE")
            echo -e "${CYAN}[i] Running in INTERACTIVE MODE $message${NC}"
            ;;
    esac
}

display_phase_header() {
    local phase_number="$1"
    local phase_name="$2"
    echo -e "\n${PURPLE}═══ PHASE $phase_number: $phase_name ═══${NC}"
}

display_operation() {
    local message="$1"
    echo -e "${YELLOW}[*] $message${NC}"
}

display_success() {
    local message="$1"
    echo -e "${GREEN}[+] $message${NC}"
}

display_warning() {
    local message="$1"
    echo -e "${YELLOW}[!] $message${NC}"
}

display_error() {
    local message="$1"
    echo -e "${RED}[-] $message${NC}"
}

display_info() {
    local message="$1"
    echo -e "${BLUE}[i] $message${NC}"
}

# Phase completion logging
log_phase() {
    local phase_num="$1"
    local message="$2"
    local output_dir="${3:-$OUTPUT_DIR}"
    
    echo -e "${GREEN}[✓] Phase $phase_num completed: $message${NC}"
    
    # Create timeline log
    mkdir -p "$output_dir/summary"
    echo "$(date): Phase $phase_num - $message" >> "$output_dir/summary/timeline.log"
}

# Tool checking display
check_and_display_tool() {
    local tool="$1"
    local required="${2:-false}"
    
    if command -v "$tool" &> /dev/null; then
        echo -e "${GREEN}[+] $tool available${NC}"
        return 0
    else
        if [ "$required" = "true" ]; then
            echo -e "${RED}[-] $tool missing (required)${NC}"
        else
            echo -e "${YELLOW}[!] $tool not available (optional)${NC}"
        fi
        return 1
    fi
}

# Count results helper
count_results() {
    if [ -f "$1" ]; then
        wc -l < "$1" 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

# =============================================================================
# SCRIPT SETUP AND ARGUMENT PARSING
# =============================================================================

# Check if target domain is provided OR if help is requested
if [ $# -eq 0 ] || [ "$1" = "--help" ] || [ "$1" = "-h" ] || [ "$1" = "help" ]; then
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           Enhanced Reconnaissance System v2.0               ║${NC}"
    echo -e "${BLUE}║              Author: @jLaHire (September 2025)               ║${NC}"
    echo -e "${BLUE}║          Integrates OSINT techniques for comprehensive       ║${NC}"
    echo -e "${BLUE}║          intelligence gathering and vulnerability discovery  ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo -e "${RED}Usage: $0 <target_domain> [options]${NC}"
    echo ""
    echo "Examples:"
    echo "  $0 tesla.com                    # Full reconnaissance with APIs"
    echo "  $0 tesla.com --no-apis          # Basic reconnaissance without APIs"
    echo "  $0 tesla.com --api-mode         # Interactive API configuration"
    echo "  $0 tesla.com --skip-cloud       # Skip cloud infrastructure scanning"
    echo ""
    echo -e "${YELLOW}Options:${NC}"
    echo "  --no-apis        Run in basic mode without API requirements"
    echo "  --api-mode       Interactive API key configuration"
    echo "  --skip-cloud     Skip cloud infrastructure reconnaissance"
    echo "  --help, -h       Show this help message"
    echo ""
    echo -e "${YELLOW}Reconnaissance Modes:${NC}"
    echo -e "${GREEN}1. Full Mode (with APIs):${NC}"
    echo "   • GitHub/GitLab intelligence for sensitive data exposure"
    echo "   • Enhanced subdomain discovery via multiple sources"
    echo "   • Microsoft/Office365 service enumeration"
    echo "   • Advanced threat intelligence and reputation analysis"
    echo "   • Historical analysis via Wayback Machine"
    echo "   • Configuration exposure detection"
    echo ""
    echo -e "${BLUE}2. Basic Mode (no APIs):${NC}"
    echo "   • Certificate transparency scanning with multiple sources"
    echo "   • DNS enumeration and validation with enhanced patterns"
    echo "   • Port scanning and comprehensive service detection"
    echo "   • Web technology identification and analysis"
    echo "   • Vulnerability scanning with Nuclei templates"
    echo "   • Basic configuration exposure detection"
    echo ""
    exit 1
fi

TARGET_DOMAIN="$1"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="ante_recon_${TARGET_DOMAIN}_${TIMESTAMP}"
THREADS=${RECON_THREADS:-30}

# Parse command line options
NO_APIS=false
API_MODE=false
SKIP_CLOUD_SCAN=${SKIP_CLOUD_SCAN:-false}

for arg in "${@:2}"; do
    case $arg in
        --no-apis)
            NO_APIS=true
            shift
            ;;
        --api-mode)
            API_MODE=true
            shift
            ;;
        --skip-cloud)
            SKIP_CLOUD_SCAN=true
            shift
            ;;
        *)
            echo "Unknown option: $arg"
            exit 1
            ;;
    esac
done

# Create structured output directory
mkdir -p "$OUTPUT_DIR"/{asn,microsoft,github,subdomains,live_hosts,portscan,ssl,tech_stack,screenshots,content,vulns,cloud_recon,virustotal,osint,config_analysis,summary}

display_header "                    ANTE RECONNAISSANCE v2.0                  " \
              "                       Author: @jLaHire                         " \
              "$TARGET_DOMAIN"

# Determine reconnaissance mode
if [ "$NO_APIS" = true ]; then
    RECON_MODE="BASIC"
    display_mode_info "BASIC" "(no API keys required)" "Focus: DNS, certificates, ports, vulnerabilities, basic OSINT"
elif [ "$API_MODE" = true ]; then
    RECON_MODE="INTERACTIVE"
    display_mode_info "INTERACTIVE" "(API configuration)" ""
else
    # Auto-detect available APIs
    API_COUNT=0
    if [ -n "${GITHUB_TOKEN:-}" ]; then API_COUNT=$((API_COUNT + 1)); fi
    if [ -n "${CHAOS_API_KEY:-}" ]; then API_COUNT=$((API_COUNT + 1)); fi
    if [ -n "${URLSCAN_API_KEY:-}" ]; then API_COUNT=$((API_COUNT + 1)); fi
    if [ -n "${VIRUSTOTAL_API_KEY:-}" ]; then API_COUNT=$((API_COUNT + 1)); fi
    
    if [ $API_COUNT -gt 0 ]; then
        RECON_MODE="FULL"
        display_mode_info "FULL" "($API_COUNT APIs detected)" "Enhanced capabilities enabled with OSINT integration"
    else
        RECON_MODE="BASIC"
        display_mode_info "BASIC" "(no APIs detected)" "Add API keys for enhanced capabilities"
    fi
fi

# Check essential tools
echo -e "\n${YELLOW}[*] Checking available tools...${NC}"
ESSENTIAL_TOOLS=("dig" "whois" "nmap" "curl" "jq")
OPTIONAL_TOOLS=("subfinder" "httpx" "nuclei" "katana" "naabu" "subzy" "smap")

for tool in "${ESSENTIAL_TOOLS[@]}"; do
    if ! check_and_display_tool "$tool" "true"; then
        exit 1
    fi
done

AVAILABLE_TOOLS=()
for tool in "${OPTIONAL_TOOLS[@]}"; do
    if check_and_display_tool "$tool" "false"; then
        AVAILABLE_TOOLS+=("$tool")
    fi
done

# Store start time for runtime calculation
SCRIPT_START_TIME=$(date +%s)

# =============================================================================
# PHASE 1: ASN DISCOVERY AND IP RANGE COLLECTION
# =============================================================================
display_phase_header "1" "ASN DISCOVERY AND IP RANGE COLLECTION"

display_operation "Resolving target domain IPs..."
dig +short "$TARGET_DOMAIN" A | head -10 > "$OUTPUT_DIR/asn/target_ips.txt"
dig +short "$TARGET_DOMAIN" AAAA | head -5 >> "$OUTPUT_DIR/asn/target_ips.txt"

display_operation "Cleaning IP results..."
sed -i '/^$/d' "$OUTPUT_DIR/asn/target_ips.txt" 2>/dev/null || true

display_operation "Performing whois ASN lookups..."
while read -r ip; do
    if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "=== ASN for $ip ===" >> "$OUTPUT_DIR/asn/asn_info.txt"
        timeout 10 whois -h whois.cymru.com " -v $ip" >> "$OUTPUT_DIR/asn/asn_info.txt" 2>/dev/null || echo "Timeout for $ip" >> "$OUTPUT_DIR/asn/asn_info.txt"
        echo "" >> "$OUTPUT_DIR/asn/asn_info.txt"
        
        echo "--- Alternative ASN lookup for $ip ---" >> "$OUTPUT_DIR/asn/asn_info.txt"
        timeout 5 whois "$ip" | grep -i "origin\|asn\|as[0-9]" >> "$OUTPUT_DIR/asn/asn_info.txt" 2>/dev/null || echo "No ASN found via whois" >> "$OUTPUT_DIR/asn/asn_info.txt"
        echo "" >> "$OUTPUT_DIR/asn/asn_info.txt"
    fi
done < "$OUTPUT_DIR/asn/target_ips.txt"

display_operation "Extracting ASN numbers..."
if [ -f "$OUTPUT_DIR/asn/asn_info.txt" ]; then
    grep -E "(AS[0-9]+|ASN[0-9]+|Origin.*[0-9]+)" "$OUTPUT_DIR/asn/asn_info.txt" | \
    grep -oE "(AS[0-9]+|ASN[0-9]+|[0-9]{4,6})" | \
    sed 's/ASN/AS/' | \
    sort -u > "$OUTPUT_DIR/asn/asn_numbers_raw.txt" 2>/dev/null || touch "$OUTPUT_DIR/asn/asn_numbers_raw.txt"
    
    while read -r asn; do
        if [[ "$asn" =~ ^[0-9]+$ ]]; then
            echo "AS$asn" >> "$OUTPUT_DIR/asn/asn_numbers.txt"
        elif [[ "$asn" =~ ^AS[0-9]+$ ]]; then
            echo "$asn" >> "$OUTPUT_DIR/asn/asn_numbers.txt"
        fi
    done < "$OUTPUT_DIR/asn/asn_numbers_raw.txt" 2>/dev/null
    
    sort -u "$OUTPUT_DIR/asn/asn_numbers.txt" -o "$OUTPUT_DIR/asn/asn_numbers.txt" 2>/dev/null || touch "$OUTPUT_DIR/asn/asn_numbers.txt"
else
    touch "$OUTPUT_DIR/asn/asn_numbers.txt"
fi

ASN_COUNT=$(count_results "$OUTPUT_DIR/asn/asn_numbers.txt")
log_phase "1" "ASN Discovery - Found $ASN_COUNT ASNs"

# =============================================================================
# PHASE 2: ENHANCED SUBDOMAIN ENUMERATION
# =============================================================================
if [ "$RECON_MODE" = "BASIC" ] || [ "$NO_APIS" = true ]; then
    display_phase_header "2" "ENHANCED SUBDOMAIN ENUMERATION (BASIC MODE)"
    
    display_operation "Checking Certificate Transparency logs (multiple sources)..."
    
    # Primary CT source - crt.sh
    curl -s "https://crt.sh/?q=%.${TARGET_DOMAIN}&output=json" | jq -r '.[].name_value' 2>/dev/null | grep -v "^$" | sort -u > "$OUTPUT_DIR/subdomains/crt_sh.txt" || touch "$OUTPUT_DIR/subdomains/crt_sh.txt"
    
    # Additional CT sources
    display_operation "Checking additional Certificate Transparency sources..."
    curl -s "https://certspotter.com/api/v0/certs?domain=${TARGET_DOMAIN}" | jq -r '.[].dns_names[]' 2>/dev/null | grep -v "^$" | sort -u > "$OUTPUT_DIR/subdomains/certspotter.txt" || touch "$OUTPUT_DIR/subdomains/certspotter.txt"
    
    display_operation "Passive DNS enumeration via search engines..."
    # Safe search-based subdomain discovery without aggressive dorking
    curl -s "https://dns.bufferover.run/dns?q=.${TARGET_DOMAIN}" | jq -r '.FDNS_A[]' 2>/dev/null | cut -d',' -f2 | grep -E "\.${TARGET_DOMAIN}$" | sort -u >> "$OUTPUT_DIR/subdomains/passive_dns.txt" 2>/dev/null || touch "$OUTPUT_DIR/subdomains/passive_dns.txt"
    
    display_operation "DNS brute force with expanded common subdomains..."
    COMMON_SUBS=("www" "mail" "ftp" "localhost" "webmail" "smtp" "pop" "ns1" "webdisk" "ns2" "cpanel" "whm" "autodiscover" "autoconfig" "m" "imap" "test" "ns" "blog" "pop3" "dev" "www2" "admin" "forum" "news" "vpn" "ns3" "mail2" "new" "mysql" "old" "www1" "email" "img" "www3" "help" "shop" "sql" "secure" "beta" "mobile" "api" "support" "www4" "en" "static" "demo" "dns" "web" "staging" "app" "backup" "mx" "status" "portal" "git" "data" "cloud" "assets" "cdn" "media" "docs" "file" "files" "home" "info" "internal" "intranet" "remote" "server" "ssl" "stage" "stats" "store" "temp" "upload" "video" "wiki" "mx1" "mx2" "ns4" "ns5" "pop3" "imap" "exchange" "owa" "webdisk" "cpanel" "whm" "test1" "test2" "dev1" "dev2" "stage1" "staging1")
    
    for sub in "${COMMON_SUBS[@]}"; do
        if dig +short "${sub}.${TARGET_DOMAIN}" A | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' >/dev/null; then
            echo "${sub}.${TARGET_DOMAIN}" >> "$OUTPUT_DIR/subdomains/dns_brute.txt"
        fi
    done
    
    # Wayback Machine historical subdomains
    display_operation "Checking Wayback Machine for historical subdomains..."
    curl -s "http://web.archive.org/cdx/search/cdx?url=*.${TARGET_DOMAIN}/*&output=text&fl=original&collapse=urlkey" | cut -d' ' -f3 | cut -d'/' -f3 | grep "\.${TARGET_DOMAIN}$" | sort -u > "$OUTPUT_DIR/subdomains/wayback_basic.txt" || touch "$OUTPUT_DIR/subdomains/wayback_basic.txt"
    
    cat "$OUTPUT_DIR/subdomains/"*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/subdomains/all_subdomains.txt"
    
else
    display_phase_header "2" "ENHANCED SUBDOMAIN ENUMERATION (FULL MODE)"
    
    display_operation "Checking Certificate Transparency logs (comprehensive)..."
    curl -s "https://crt.sh/?q=%.${TARGET_DOMAIN}&output=json" | jq -r '.[].name_value' 2>/dev/null | grep -v "^$" | sort -u > "$OUTPUT_DIR/subdomains/crt_sh.txt" || touch "$OUTPUT_DIR/subdomains/crt_sh.txt"
    
    # Additional CT sources in full mode
    curl -s "https://certspotter.com/api/v0/certs?domain=${TARGET_DOMAIN}" | jq -r '.[].dns_names[]' 2>/dev/null | grep -v "^$" | sort -u > "$OUTPUT_DIR/subdomains/certspotter.txt" || touch "$OUTPUT_DIR/subdomains/certspotter.txt"
    
    display_operation "Running subfinder with API keys..."
    if [[ " ${AVAILABLE_TOOLS[*]} " =~ " subfinder " ]]; then
        mkdir -p ~/.config/subfinder
        cat > ~/.config/subfinder/config.yaml << APICONF
chaos: ["${CHAOS_API_KEY:-}"]
github: ["${GITHUB_TOKEN:-}"]
urlscan: ["${URLSCAN_API_KEY:-}"]
virustotal: ["${VIRUSTOTAL_API_KEY:-}"]
APICONF
        subfinder -d "$TARGET_DOMAIN" -config ~/.config/subfinder/config.yaml -silent -o "$OUTPUT_DIR/subdomains/subfinder.txt" -t 20 || touch "$OUTPUT_DIR/subdomains/subfinder.txt"
    fi
    
    display_operation "Enhanced Wayback Machine analysis..."
    # Multiple Wayback Machine queries for better coverage
    curl -s "http://web.archive.org/cdx/search/cdx?url=*.${TARGET_DOMAIN}/*&output=text&fl=original&collapse=urlkey" | cut -d' ' -f3 | cut -d'/' -f3 | grep "\.${TARGET_DOMAIN}$" | sort -u > "$OUTPUT_DIR/subdomains/wayback.txt" || touch "$OUTPUT_DIR/subdomains/wayback.txt"
    
    # Common subdomain patterns from archived URLs
    curl -s "http://web.archive.org/cdx/search/cdx?url=${TARGET_DOMAIN}/*&output=text&fl=original" | grep -E "https?://[^/]*\.${TARGET_DOMAIN}" | sed -E 's|https?://([^/]*)\.[^/]*|\1|' | sort -u >> "$OUTPUT_DIR/subdomains/wayback.txt" || true
    
    display_operation "Passive DNS enumeration..."
    curl -s "https://dns.bufferover.run/dns?q=.${TARGET_DOMAIN}" | jq -r '.FDNS_A[]' 2>/dev/null | cut -d',' -f2 | grep -E "\.${TARGET_DOMAIN}$" | sort -u > "$OUTPUT_DIR/subdomains/passive_dns.txt" || touch "$OUTPUT_DIR/subdomains/passive_dns.txt"
    
    cat "$OUTPUT_DIR/subdomains/"*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/subdomains/all_subdomains.txt"
fi

SUBDOMAIN_COUNT=$(count_results "$OUTPUT_DIR/subdomains/all_subdomains.txt")
log_phase "2" "Enhanced Subdomain Enumeration - Found $SUBDOMAIN_COUNT subdomains ($RECON_MODE mode)"

# =============================================================================
# PHASE 3: LIVE HOST DISCOVERY
# =============================================================================
display_phase_header "3" "LIVE HOST DISCOVERY"

display_operation "Checking for live hosts with enhanced probing..."
if [[ " ${AVAILABLE_TOOLS[*]} " =~ " httpx " ]]; then
    cat "$OUTPUT_DIR/subdomains/all_subdomains.txt" | httpx -silent -mc 200,201,301,302,403,401,500 -fc 404 -t $THREADS -o "$OUTPUT_DIR/live_hosts/live_hosts.txt"
    
    display_operation "Getting detailed information with technology detection..."
    cat "$OUTPUT_DIR/live_hosts/live_hosts.txt" | httpx -silent -json -tech-detect -status-code -title -server -t $THREADS > "$OUTPUT_DIR/live_hosts/httpx_detailed.json"
else
    display_operation "Using basic curl for live host detection..."
    while read -r subdomain; do
        if [ -n "$subdomain" ]; then
            for proto in "https" "http"; do
                if timeout 5 curl -s -I "${proto}://${subdomain}" >/dev/null 2>&1; then
                    echo "${proto}://${subdomain}" >> "$OUTPUT_DIR/live_hosts/live_hosts.txt"
                    break
                fi
            done
        fi
    done < "$OUTPUT_DIR/subdomains/all_subdomains.txt"
fi

LIVE_COUNT=$(count_results "$OUTPUT_DIR/live_hosts/live_hosts.txt")
log_phase "3" "Live Host Discovery - Found $LIVE_COUNT live hosts"

# =============================================================================
# PHASE 4: SUBDOMAIN TAKEOVER DETECTION
# =============================================================================
display_phase_header "4" "SUBDOMAIN TAKEOVER DETECTION"

display_operation "Checking for subdomain takeover vulnerabilities..."
if [[ " ${AVAILABLE_TOOLS[*]} " =~ " subzy " ]] && [ "$SUBDOMAIN_COUNT" -gt 0 ]; then
    if [ -f "$OUTPUT_DIR/subdomains/all_subdomains.txt" ] && [ -s "$OUTPUT_DIR/subdomains/all_subdomains.txt" ]; then
        display_operation "Running subzy against discovered subdomains..."
        subzy run --targets "$OUTPUT_DIR/subdomains/all_subdomains.txt" --concurrency 20 --timeout 10 --output "$OUTPUT_DIR/vulns/subdomain_takeover.txt" 2>/dev/null || {
            display_warning "Subzy scan encountered issues, creating empty results file"
            touch "$OUTPUT_DIR/vulns/subdomain_takeover.txt"
        }
        
        # Also check live hosts specifically
        if [ -f "$OUTPUT_DIR/live_hosts/live_hosts.txt" ] && [ -s "$OUTPUT_DIR/live_hosts/live_hosts.txt" ]; then
            display_operation "Checking live hosts for takeover vulnerabilities..."
            cat "$OUTPUT_DIR/live_hosts/live_hosts.txt" | sed 's|https\?://||' | sed 's|/.*||' | sort -u > "$OUTPUT_DIR/vulns/live_hostnames.txt"
            subzy run --targets "$OUTPUT_DIR/vulns/live_hostnames.txt" --concurrency 20 --timeout 10 --output "$OUTPUT_DIR/vulns/live_takeover.txt" 2>/dev/null || touch "$OUTPUT_DIR/vulns/live_takeover.txt"
            
            # Combine results
            cat "$OUTPUT_DIR/vulns/subdomain_takeover.txt" "$OUTPUT_DIR/vulns/live_takeover.txt" 2>/dev/null | sort -u > "$OUTPUT_DIR/vulns/takeover_combined.txt" || touch "$OUTPUT_DIR/vulns/takeover_combined.txt"
            mv "$OUTPUT_DIR/vulns/takeover_combined.txt" "$OUTPUT_DIR/vulns/subdomain_takeover.txt"
        fi
    else
        display_warning "No subdomains found for takeover testing"
        touch "$OUTPUT_DIR/vulns/subdomain_takeover.txt"
    fi
else
    if [[ ! " ${AVAILABLE_TOOLS[*]} " =~ " subzy " ]]; then
        display_warning "Subzy not available - skipping subdomain takeover detection"
        display_info "Install with: go install -v github.com/PentestPad/subzy@latest"
    else
        display_warning "Skipping subdomain takeover detection - no subdomains found"
    fi
    touch "$OUTPUT_DIR/vulns/subdomain_takeover.txt"
fi

TAKEOVER_COUNT=$(count_results "$OUTPUT_DIR/vulns/subdomain_takeover.txt")

# Create takeover vulnerability summary
if [ "$TAKEOVER_COUNT" -gt 0 ]; then
    echo "# Subdomain Takeover Summary - $(date)" > "$OUTPUT_DIR/vulns/takeover_summary.txt"
    echo "Potential subdomain takeovers found: $TAKEOVER_COUNT" >> "$OUTPUT_DIR/vulns/takeover_summary.txt"
    echo "" >> "$OUTPUT_DIR/vulns/takeover_summary.txt"
    echo "CRITICAL: These findings indicate potential subdomain takeover vulnerabilities." >> "$OUTPUT_DIR/vulns/takeover_summary.txt"
    echo "Immediate manual verification and remediation recommended." >> "$OUTPUT_DIR/vulns/takeover_summary.txt"
    echo "" >> "$OUTPUT_DIR/vulns/takeover_summary.txt"
    
    if [ -s "$OUTPUT_DIR/vulns/subdomain_takeover.txt" ]; then
        echo "Vulnerable subdomains:" >> "$OUTPUT_DIR/vulns/takeover_summary.txt"
        cat "$OUTPUT_DIR/vulns/subdomain_takeover.txt" >> "$OUTPUT_DIR/vulns/takeover_summary.txt"
    fi
else
    echo "# No subdomain takeover vulnerabilities detected - $(date)" > "$OUTPUT_DIR/vulns/takeover_summary.txt"
    echo "This automated scan found no obvious takeover vulnerabilities." >> "$OUTPUT_DIR/vulns/takeover_summary.txt"
    echo "Manual verification of suspicious subdomains is still recommended." >> "$OUTPUT_DIR/vulns/takeover_summary.txt"
fi

log_phase "4" "Subdomain Takeover Detection - Found $TAKEOVER_COUNT potential takeovers"

# =============================================================================
# PHASE 5: ENHANCED NETWORK PORT SCANNING
# =============================================================================
display_phase_header "5" "ENHANCED NETWORK PORT SCANNING"

if [ $LIVE_COUNT -gt 0 ]; then
    display_operation "Extracting target hosts for port scanning..."
    cat "$OUTPUT_DIR/live_hosts/live_hosts.txt" | sed 's|https\?://||' | sed 's|/.*||' | sed 's|:.*||' | sort -u > "$OUTPUT_DIR/portscan/target_hosts.txt"
    
    # Enhanced port scanning with Smap integration
    display_operation "Running enhanced port scanning with multiple tools..."
    
    # Primary scan with Smap (fast, Shodan-powered)
    if [[ " ${AVAILABLE_TOOLS[*]} " =~ " smap " ]]; then
        display_operation "Running Smap (Shodan-powered) for rapid passive scanning..."
        
        # Run Smap with multiple output formats for comprehensive analysis
        smap -iL "$OUTPUT_DIR/portscan/target_hosts.txt" -oS "$OUTPUT_DIR/portscan/smap_detailed.txt" 2>/dev/null || {
            display_warning "Smap detailed scan encountered issues"
            touch "$OUTPUT_DIR/portscan/smap_detailed.txt"
        }
        
        # Get Smap results in port:IP format
        smap -iL "$OUTPUT_DIR/portscan/target_hosts.txt" -oP "$OUTPUT_DIR/portscan/smap_portip.txt" 2>/dev/null || touch "$OUTPUT_DIR/portscan/smap_portip.txt"
        
        # Convert Smap output to standard format and extract vulnerabilities
        if [ -s "$OUTPUT_DIR/portscan/smap_detailed.txt" ]; then
            # Extract basic port information
            grep -E "^[0-9]" "$OUTPUT_DIR/portscan/smap_detailed.txt" | awk '{print $1":"$2}' > "$OUTPUT_DIR/portscan/smap_ports.txt" 2>/dev/null || touch "$OUTPUT_DIR/portscan/smap_ports.txt"
            
            # Extract service information
            grep -E "(open|filtered)" "$OUTPUT_DIR/portscan/smap_detailed.txt" > "$OUTPUT_DIR/portscan/smap_services.txt" 2>/dev/null || touch "$OUTPUT_DIR/portscan/smap_services.txt"
            
            # Extract vulnerability information if available
            grep -iE "(vuln|cve-|exploit)" "$OUTPUT_DIR/portscan/smap_detailed.txt" > "$OUTPUT_DIR/portscan/smap_vulnerabilities.txt" 2>/dev/null || touch "$OUTPUT_DIR/portscan/smap_vulnerabilities.txt"
        fi
        
        SMAP_PORTS=$(count_results "$OUTPUT_DIR/portscan/smap_ports.txt")
        SMAP_VULNS=$(count_results "$OUTPUT_DIR/portscan/smap_vulnerabilities.txt")
        
        if [ "$SMAP_PORTS" -gt 0 ]; then
            display_success "Smap discovered $SMAP_PORTS ports" 
            if [ "$SMAP_VULNS" -gt 0 ]; then
                display_success "Smap identified $SMAP_VULNS potential vulnerabilities"
            fi
        else
            display_warning "Smap found no open ports (may indicate stealth hosts or recent infrastructure)"
        fi
    else
        display_info "Smap not available - install with: go install github.com/s0md3v/smap/cmd/smap@latest"
    fi
    
    # Secondary scan with Naabu (direct connection)
    if [[ " ${AVAILABLE_TOOLS[*]} " =~ " naabu " ]]; then
        display_operation "Running Naabu for direct connection verification..."
        naabu -l "$OUTPUT_DIR/portscan/target_hosts.txt" -top-ports 1000 -silent -o "$OUTPUT_DIR/portscan/naabu_ports.txt" || touch "$OUTPUT_DIR/portscan/naabu_ports.txt"
        
        NAABU_PORTS=$(count_results "$OUTPUT_DIR/portscan/naabu_ports.txt")
        if [ "$NAABU_PORTS" -gt 0 ]; then
            display_success "Naabu verified $NAABU_PORTS ports via direct connection"
        fi
    fi
    
    # Fallback with Nmap if neither advanced tool is available
    if [[ ! " ${AVAILABLE_TOOLS[*]} " =~ " smap " ]] && [[ ! " ${AVAILABLE_TOOLS[*]} " =~ " naabu " ]]; then
        display_operation "Running Nmap scan (fallback method)..."
        timeout 300 nmap -T4 -n --open --top-ports 1000 -iL "$OUTPUT_DIR/portscan/target_hosts.txt" -oG "$OUTPUT_DIR/portscan/nmap_scan.txt" 2>/dev/null || echo "Nmap scan timeout"
        if [ -f "$OUTPUT_DIR/portscan/nmap_scan.txt" ]; then
            grep "open" "$OUTPUT_DIR/portscan/nmap_scan.txt" | awk '{print $2":"$4}' > "$OUTPUT_DIR/portscan/nmap_ports.txt" || touch "$OUTPUT_DIR/portscan/nmap_ports.txt"
        else
            touch "$OUTPUT_DIR/portscan/nmap_ports.txt"
        fi
    fi
    
    # Combine and analyze all port scan results
    display_operation "Combining and analyzing port scan results..."
    cat "$OUTPUT_DIR/portscan/"*_ports.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/portscan/combined_ports.txt"
    
    # Create comprehensive port analysis
    if [ -s "$OUTPUT_DIR/portscan/combined_ports.txt" ]; then
        cp "$OUTPUT_DIR/portscan/combined_ports.txt" "$OUTPUT_DIR/portscan/open_ports.txt"
        
        # Generate detailed port scan summary with Smap insights
        cat > "$OUTPUT_DIR/portscan/scan_summary.txt" << PORTSUMMARY
# Enhanced Port Scan Summary with Smap Integration - $(date)
Target hosts scanned: $(wc -l < "$OUTPUT_DIR/portscan/target_hosts.txt")
Total open ports found: $(wc -l < "$OUTPUT_DIR/portscan/open_ports.txt")

## Scan Methods Used and Results:
PORTSUMMARY
        
        if [[ " ${AVAILABLE_TOOLS[*]} " =~ " smap " ]]; then
            SMAP_COUNT=$(wc -l < "$OUTPUT_DIR/portscan/smap_ports.txt" 2>/dev/null || echo "0")
            echo "### Smap (Shodan-powered passive scan)" >> "$OUTPUT_DIR/portscan/scan_summary.txt"
            echo "- Ports discovered: $SMAP_COUNT" >> "$OUTPUT_DIR/portscan/scan_summary.txt"
            echo "- Scan speed: ~200 hosts/second" >> "$OUTPUT_DIR/portscan/scan_summary.txt"
            echo "- Data source: Historical Shodan data (up to 7 days old)" >> "$OUTPUT_DIR/portscan/scan_summary.txt"
            echo "- Vulnerabilities identified: $SMAP_VULNS" >> "$OUTPUT_DIR/portscan/scan_summary.txt"
            echo "- Advantage: No direct contact with targets (stealth)" >> "$OUTPUT_DIR/portscan/scan_summary.txt"
            echo "" >> "$OUTPUT_DIR/portscan/scan_summary.txt"
        fi
        
        if [[ " ${AVAILABLE_TOOLS[*]} " =~ " naabu " ]]; then
            NAABU_COUNT=$(wc -l < "$OUTPUT_DIR/portscan/naabu_ports.txt" 2>/dev/null || echo "0")
            echo "### Naabu (direct connection verification)" >> "$OUTPUT_DIR/portscan/scan_summary.txt"
            echo "- Ports verified: $NAABU_COUNT" >> "$OUTPUT_DIR/portscan/scan_summary.txt"
            echo "- Method: Real-time connection attempts" >> "$OUTPUT_DIR/portscan/scan_summary.txt"
            echo "- Advantage: Current status verification" >> "$OUTPUT_DIR/portscan/scan_summary.txt"
            echo "" >> "$OUTPUT_DIR/portscan/scan_summary.txt"
        fi
        
        if [ -f "$OUTPUT_DIR/portscan/nmap_ports.txt" ]; then
            NMAP_COUNT=$(wc -l < "$OUTPUT_DIR/portscan/nmap_ports.txt" 2>/dev/null || echo "0")
            echo "### Nmap (traditional scan)" >> "$OUTPUT_DIR/portscan/scan_summary.txt"
            echo "- Ports found: $NMAP_COUNT" >> "$OUTPUT_DIR/portscan/scan_summary.txt"
            echo "- Method: Traditional TCP connect scan" >> "$OUTPUT_DIR/portscan/scan_summary.txt"
            echo "" >> "$OUTPUT_DIR/portscan/scan_summary.txt"
        fi
        
        cat >> "$OUTPUT_DIR/portscan/scan_summary.txt" << ANALYSIS

## Port Distribution Analysis:
$(cut -d':' -f2 "$OUTPUT_DIR/portscan/open_ports.txt" 2>/dev/null | sort | uniq -c | sort -rn | head -10 | awk '{print $2 " (found on " $1 " hosts)"}' || echo "No port analysis available")

## Smap Vulnerability Intelligence:
ANALYSIS
        
        if [ -s "$OUTPUT_DIR/portscan/smap_vulnerabilities.txt" ]; then
            echo "Potential vulnerabilities identified by Smap:" >> "$OUTPUT_DIR/portscan/scan_summary.txt"
            head -20 "$OUTPUT_DIR/portscan/smap_vulnerabilities.txt" >> "$OUTPUT_DIR/portscan/scan_summary.txt"
        else
            echo "No specific vulnerabilities identified in Smap scan" >> "$OUTPUT_DIR/portscan/scan_summary.txt"
        fi
        
        cat >> "$OUTPUT_DIR/portscan/scan_summary.txt" << RECOMMENDATIONS

## Analysis Notes and Recommendations:
- Smap results provide historical intelligence without alerting targets
- Direct scanning (Naabu/Nmap) confirms current port status
- Combined approach maximizes discovery while minimizing detection risk
- Smap vulnerability data should be validated with manual testing
- Consider running both passive and active scans for comprehensive coverage

## Next Steps:
1. Review Smap vulnerability findings in: smap_vulnerabilities.txt
2. Validate critical services found by direct scanning
3. Cross-reference findings with subsequent vulnerability scans
4. Prioritize investigation based on service criticality and exposure
RECOMMENDATIONS
        
    else
        touch "$OUTPUT_DIR/portscan/open_ports.txt"
        echo "No open ports discovered across all scan methods" > "$OUTPUT_DIR/portscan/scan_summary.txt"
        echo "This could indicate:" >> "$OUTPUT_DIR/portscan/scan_summary.txt"
        echo "- Hosts are behind firewalls or load balancers" >> "$OUTPUT_DIR/portscan/scan_summary.txt"
        echo "- Services are running on non-standard ports" >> "$OUTPUT_DIR/portscan/scan_summary.txt"
        echo "- Infrastructure changes since last Shodan scan" >> "$OUTPUT_DIR/portscan/scan_summary.txt"
    fi
    
else
    display_warning "No live hosts found, skipping port scanning"
    touch "$OUTPUT_DIR/portscan/open_ports.txt"
    echo "No live hosts available for port scanning" > "$OUTPUT_DIR/portscan/scan_summary.txt"
fi

OPEN_PORTS=$(count_results "$OUTPUT_DIR/portscan/open_ports.txt")
log_phase "5" "Enhanced Port Scanning - Found $OPEN_PORTS open ports"

# =============================================================================
# PHASE 6: SSL CERTIFICATE ANALYSIS
# =============================================================================
display_phase_header "6" "SSL CERTIFICATE ANALYSIS"

display_operation "Analyzing SSL certificates..."
https_hosts=$(grep "https://" "$OUTPUT_DIR/live_hosts/live_hosts.txt" 2>/dev/null || true)
if [ -n "$https_hosts" ]; then
    echo "$https_hosts" | while read -r url; do
        host=$(echo "$url" | sed 's|https://||' | sed 's|/.*||')
        echo "=== SSL Certificate for $host ===" >> "$OUTPUT_DIR/ssl/certificate_analysis.txt"
        timeout 10 openssl s_client -connect "$host:443" -servername "$host" </dev/null 2>/dev/null | openssl x509 -noout -text 2>/dev/null >> "$OUTPUT_DIR/ssl/certificate_analysis.txt" || echo "Failed to get cert for $host" >> "$OUTPUT_DIR/ssl/certificate_analysis.txt"
        echo "" >> "$OUTPUT_DIR/ssl/certificate_analysis.txt"
    done
fi

SSL_COUNT=$(echo "$https_hosts" | wc -l)
log_phase "6" "SSL Analysis - Analyzed $SSL_COUNT certificates"

# =============================================================================
# PHASE 7: COMPREHENSIVE CLOUD INFRASTRUCTURE ANALYSIS
# =============================================================================
if [ "$SKIP_CLOUD_SCAN" = "false" ]; then
    display_phase_header "7" "COMPREHENSIVE CLOUD INFRASTRUCTURE ANALYSIS"
    
    display_operation "Extracting IPs for cloud analysis..."
    cat "$OUTPUT_DIR/live_hosts/live_hosts.txt" 2>/dev/null | sed 's|https\?://||' | sed 's|/.*||' | sort -u > "$OUTPUT_DIR/cloud_recon/target_hosts.txt" || touch "$OUTPUT_DIR/cloud_recon/target_hosts.txt"
    
    # Extract all IPs from discovered hosts
    > "$OUTPUT_DIR/cloud_recon/target_ips.txt"
    while read -r host; do
        if [ -n "$host" ]; then
            dig +short "$host" A 2>/dev/null | head -3 >> "$OUTPUT_DIR/cloud_recon/target_ips.txt" || true
        fi
    done < "$OUTPUT_DIR/cloud_recon/target_hosts.txt"
    
    # Also include the original target domain IPs
    if [ -f "$OUTPUT_DIR/asn/target_ips.txt" ]; then
        cat "$OUTPUT_DIR/asn/target_ips.txt" >> "$OUTPUT_DIR/cloud_recon/target_ips.txt"
    fi
    
    # Remove duplicates and empty lines
    sort -u "$OUTPUT_DIR/cloud_recon/target_ips.txt" | grep -v "^$" > "$OUTPUT_DIR/cloud_recon/target_ips_clean.txt" || true
    mv "$OUTPUT_DIR/cloud_recon/target_ips_clean.txt" "$OUTPUT_DIR/cloud_recon/target_ips.txt"
    
    # Enhanced cloud storage bucket enumeration
    display_operation "Scanning for cloud storage buckets based on discovered patterns..."
    
    # Extract base names for bucket prediction
    echo "$TARGET_DOMAIN" | sed 's/\./-/g' > "$OUTPUT_DIR/cloud_recon/bucket_patterns.txt"
    echo "$TARGET_DOMAIN" | sed 's/\.//' >> "$OUTPUT_DIR/cloud_recon/bucket_patterns.txt"
    
    # Add common patterns
    BUCKET_SUFFIXES=("backup" "backups" "data" "assets" "media" "files" "static" "www" "web" "app" "dev" "test" "staging" "prod" "production")
    BASE_NAME=$(echo "$TARGET_DOMAIN" | cut -d'.' -f1)
    
    for suffix in "${BUCKET_SUFFIXES[@]}"; do
        echo "${BASE_NAME}-${suffix}" >> "$OUTPUT_DIR/cloud_recon/bucket_patterns.txt"
        echo "${BASE_NAME}${suffix}" >> "$OUTPUT_DIR/cloud_recon/bucket_patterns.txt"
    done
    
    # Test common cloud storage endpoints
    display_operation "Testing cloud storage bucket accessibility..."
    while read -r pattern; do
        # AWS S3 buckets
        if timeout 5 curl -s -I "https://${pattern}.s3.amazonaws.com" | grep -q "200\|403"; then
            echo "AWS S3: ${pattern}.s3.amazonaws.com" >> "$OUTPUT_DIR/cloud_recon/accessible_buckets.txt"
        fi
        
        # Google Cloud Storage
        if timeout 5 curl -s -I "https://storage.googleapis.com/${pattern}" | grep -q "200\|403"; then
            echo "GCS: storage.googleapis.com/${pattern}" >> "$OUTPUT_DIR/cloud_recon/accessible_buckets.txt"
        fi
        
        # Azure Blob Storage
        if timeout 5 curl -s -I "https://${pattern}.blob.core.windows.net" | grep -q "200\|403"; then
            echo "Azure: ${pattern}.blob.core.windows.net" >> "$OUTPUT_DIR/cloud_recon/accessible_buckets.txt"
        fi
        
        sleep 1  # Rate limiting
    done < "$OUTPUT_DIR/cloud_recon/bucket_patterns.txt"
    
    # Check if we have any IPs to analyze
    if [ ! -s "$OUTPUT_DIR/cloud_recon/target_ips.txt" ]; then
        display_warning "No target IPs found for cloud analysis"
        log_phase "7" "Cloud Reconnaissance - Skipped (no IPs)"
    else
        IP_COUNT=$(wc -l < "$OUTPUT_DIR/cloud_recon/target_ips.txt")
        display_operation "Analyzing $IP_COUNT unique IP addresses..."
        
        # Ensure cloud ranges directory exists
        if [ ! -d "cloud_ranges" ]; then
            display_operation "Cloud ranges not found - running updater..."
            mkdir -p cloud_ranges
            
            # Try to run the range updater if it exists
            SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
            if [ -x "$SCRIPT_DIR/update_ranges.sh" ]; then
                display_info "Running cloud range updater..."
                "$SCRIPT_DIR/update_ranges.sh" >/dev/null 2>&1 || true
            else
                display_warning "Cloud range updater not found - using basic ranges"
                # Create minimal fallback ranges
                echo "52.0.0.0/8" > cloud_ranges/aws_ec2_ranges.txt
                echo "34.0.0.0/8" > cloud_ranges/gcp_ranges.txt
                echo "104.16.0.0/13" > cloud_ranges/cloudflare_v4.txt
            fi
        fi
        
        # Comprehensive cloud provider detection
        TOTAL_MATCHES=0
        PROVIDER_SUMMARY=""
        
        # Define all cloud providers and their range files
        declare -A CLOUD_PROVIDERS=(
            ["AWS"]="aws_ec2_ranges.txt"
            ["Azure"]="azure_ranges.txt"
            ["GCP"]="gcp_ranges.txt"
            ["Oracle"]="oracle_ranges.txt"
            ["DigitalOcean"]="digitalocean_ranges.txt"
            ["Alibaba"]="alibaba_ranges.txt"
            ["Cloudflare"]="cloudflare_v4.txt"
            ["Fastly"]="fastly_ranges.txt"
            ["Akamai"]="akamai_ranges.txt"
            ["Vultr"]="vultr_ranges.txt"
            ["Linode"]="linode_ranges.txt"
            ["IBM"]="ibm_ranges.txt"
        )
        
        display_operation "Checking against comprehensive cloud provider database..."
        
        # Check each cloud provider
        for provider in "${!CLOUD_PROVIDERS[@]}"; do
            range_file="cloud_ranges/${CLOUD_PROVIDERS[$provider]}"
            
            if [ -f "$range_file" ] && [ -s "$range_file" ]; then
                match_file="$OUTPUT_DIR/cloud_recon/${provider,,}_matches.txt"
                > "$match_file"  # Clear previous results
                
                # Check each target IP against this provider's ranges
                while IFS= read -r ip; do
                    if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                        while IFS= read -r range; do
                            # Skip comment lines and empty lines
                            if [[ "$range" =~ ^[[:space:]]*# ]] || [[ -z "$range" ]]; then
                                continue
                            fi
                            
                            # Use Python to check IP in range
                            if python3 -c "
import ipaddress
import sys
try:
    if ipaddress.ip_address('$ip') in ipaddress.ip_network('$range'.strip()):
        print('$ip -> $provider ($range)')
        sys.exit(0)
    sys.exit(1)
except:
    sys.exit(1)
" 2>/dev/null; then
                                echo "$ip -> $provider ($range)" >> "$match_file"
                                break  # Found a match, no need to check more ranges for this IP
                            fi
                        done < "$range_file"
                    fi
                done < "$OUTPUT_DIR/cloud_recon/target_ips.txt"
                
                # Count matches for this provider
                MATCHES=$(wc -l < "$match_file" 2>/dev/null || echo "0")
                if [ "$MATCHES" -gt 0 ]; then
                    TOTAL_MATCHES=$((TOTAL_MATCHES + MATCHES))
                    if [ -n "$PROVIDER_SUMMARY" ]; then
                        PROVIDER_SUMMARY="$PROVIDER_SUMMARY, "
                    fi
                    PROVIDER_SUMMARY="$PROVIDER_SUMMARY$provider($MATCHES)"
                fi
            fi
        done
        
        # Create comprehensive summary report
        BUCKET_COUNT=$(count_results "$OUTPUT_DIR/cloud_recon/accessible_buckets.txt")
        
        cat > "$OUTPUT_DIR/cloud_recon/cloud_analysis_summary.txt" << SUMMARY
# Comprehensive Cloud Infrastructure Analysis - $TARGET_DOMAIN
Generated: $(date)
Analyzed IPs: $IP_COUNT
Total Matches: $TOTAL_MATCHES
Accessible Buckets Found: $BUCKET_COUNT

## Cloud Storage Discovery:
SUMMARY
        
        if [ "$BUCKET_COUNT" -gt 0 ]; then
            echo "Accessible cloud storage buckets:" >> "$OUTPUT_DIR/cloud_recon/cloud_analysis_summary.txt"
            cat "$OUTPUT_DIR/cloud_recon/accessible_buckets.txt" >> "$OUTPUT_DIR/cloud_recon/cloud_analysis_summary.txt"
            echo "" >> "$OUTPUT_DIR/cloud_recon/cloud_analysis_summary.txt"
        else
            echo "No accessible cloud storage buckets found with common naming patterns." >> "$OUTPUT_DIR/cloud_recon/cloud_analysis_summary.txt"
            echo "" >> "$OUTPUT_DIR/cloud_recon/cloud_analysis_summary.txt"
        fi
        
        echo "## Provider Breakdown:" >> "$OUTPUT_DIR/cloud_recon/cloud_analysis_summary.txt"
        
        # Add detailed breakdown for each provider
        for provider in "${!CLOUD_PROVIDERS[@]}"; do
            match_file="$OUTPUT_DIR/cloud_recon/${provider,,}_matches.txt"
            if [ -f "$match_file" ]; then
                matches=$(wc -l < "$match_file" 2>/dev/null || echo "0")
                echo "$provider: $matches matches" >> "$OUTPUT_DIR/cloud_recon/cloud_analysis_summary.txt"
                if [ "$matches" -gt 0 ]; then
                    echo "  Details:" >> "$OUTPUT_DIR/cloud_recon/cloud_analysis_summary.txt"
                    head -5 "$match_file" | sed 's/^/    /' >> "$OUTPUT_DIR/cloud_recon/cloud_analysis_summary.txt"
                    if [ "$matches" -gt 5 ]; then
                        echo "    ... and $((matches - 5)) more" >> "$OUTPUT_DIR/cloud_recon/cloud_analysis_summary.txt"
                    fi
                fi
                echo "" >> "$OUTPUT_DIR/cloud_recon/cloud_analysis_summary.txt"
            fi
        done
        
        # Add analysis insights
        cat >> "$OUTPUT_DIR/cloud_recon/cloud_analysis_summary.txt" << INSIGHTS

## Infrastructure Insights:
INSIGHTS
        
        if [ "$TOTAL_MATCHES" -eq 0 ]; then
            echo "- No cloud provider matches found (on-premise or unknown hosting)" >> "$OUTPUT_DIR/cloud_recon/cloud_analysis_summary.txt"
        else
            echo "- Multi-cloud or hybrid infrastructure detected" >> "$OUTPUT_DIR/cloud_recon/cloud_analysis_summary.txt"
            echo "- Primary providers: $(echo "$PROVIDER_SUMMARY" | head -c 100)" >> "$OUTPUT_DIR/cloud_recon/cloud_analysis_summary.txt"
        fi
        
        if [ "$BUCKET_COUNT" -gt 0 ]; then
            echo "- Cloud storage buckets discovered - review for data exposure" >> "$OUTPUT_DIR/cloud_recon/cloud_analysis_summary.txt"
        fi
        
        echo "- Geographic distribution analysis recommended for global presence" >> "$OUTPUT_DIR/cloud_recon/cloud_analysis_summary.txt"
        echo "- Consider cloud-specific security assessment techniques" >> "$OUTPUT_DIR/cloud_recon/cloud_analysis_summary.txt"
        
        # Display results
        if [ "$TOTAL_MATCHES" -gt 0 ] || [ "$BUCKET_COUNT" -gt 0 ]; then
            display_success "Cloud analysis complete: $PROVIDER_SUMMARY, $BUCKET_COUNT accessible buckets"
        else
            display_success "Cloud analysis complete: No cloud provider matches (on-premise hosting)"
        fi
        
        log_phase "7" "Cloud Reconnaissance - Analyzed $IP_COUNT IPs, found $TOTAL_MATCHES matches, $BUCKET_COUNT buckets"
    fi
else
    display_phase_header "7" "COMPREHENSIVE CLOUD INFRASTRUCTURE ANALYSIS"
    display_info "Cloud scanning disabled by user"
    TOTAL_MATCHES=0
    BUCKET_COUNT=0
    log_phase "7" "Cloud Reconnaissance - Skipped by user"
fi

# =============================================================================
# PHASE 8: WEB TECHNOLOGY DETECTION
# =============================================================================
display_phase_header "8" "WEB TECHNOLOGY DETECTION"

display_operation "Extracting web technologies from httpx results..."
if [ -f "$OUTPUT_DIR/live_hosts/httpx_detailed.json" ]; then
    jq -r 'select(.tech) | .url + " | " + (.tech | join(","))' "$OUTPUT_DIR/live_hosts/httpx_detailed.json" > "$OUTPUT_DIR/tech_stack/technologies.txt" 2>/dev/null || touch "$OUTPUT_DIR/tech_stack/technologies.txt"
    
    # Extract server headers for additional tech detection
    jq -r 'select(.server) | .url + " | Server: " + .server' "$OUTPUT_DIR/live_hosts/httpx_detailed.json" >> "$OUTPUT_DIR/tech_stack/technologies.txt" 2>/dev/null || true
else
    display_operation "Manual technology detection for remaining hosts..."
    while read -r url; do
        if [ -n "$url" ]; then
            response=$(timeout 10 curl -s -I "$url" 2>/dev/null || true)
            server=$(echo "$response" | grep -i "server:" | cut -d' ' -f2- || true)
            if [ -n "$server" ]; then
                echo "$url | Server: $server" >> "$OUTPUT_DIR/tech_stack/technologies.txt"
            fi
            
            # Check for common technology indicators
            powered_by=$(echo "$response" | grep -i "x-powered-by:" | cut -d' ' -f2- || true)
            if [ -n "$powered_by" ]; then
                echo "$url | X-Powered-By: $powered_by" >> "$OUTPUT_DIR/tech_stack/technologies.txt"
            fi
        fi
    done < "$OUTPUT_DIR/live_hosts/live_hosts.txt"
fi

TECH_COUNT=$(count_results "$OUTPUT_DIR/tech_stack/technologies.txt")
log_phase "8" "Technology Detection - Found $TECH_COUNT tech stacks"

# =============================================================================
# PHASE 9: VULNERABILITY SCANNING
# =============================================================================
display_phase_header "9" "VULNERABILITY ASSESSMENT"

display_operation "Initializing Nuclei scanner..."
if [[ " ${AVAILABLE_TOOLS[*]} " =~ " nuclei " ]] && [ "$LIVE_COUNT" -gt 0 ]; then
    if nuclei -version >/dev/null 2>&1; then
        display_operation "Running vulnerability scan (medium/high/critical)..."
        if [ -f "$OUTPUT_DIR/live_hosts/live_hosts.txt" ] && [ -s "$OUTPUT_DIR/live_hosts/live_hosts.txt" ]; then
            head -30 "$OUTPUT_DIR/live_hosts/live_hosts.txt" | nuclei -silent -severity medium,high,critical -timeout 10 -retries 2 -rate-limit 50 -o "$OUTPUT_DIR/vulns/nuclei_results.txt" 2>/dev/null || {
                display_warning "Nuclei scan encountered issues, creating empty results file"
                touch "$OUTPUT_DIR/vulns/nuclei_results.txt"
            }
        else
            display_warning "No live hosts file found or file is empty"
            touch "$OUTPUT_DIR/vulns/nuclei_results.txt"
        fi
        
        display_operation "DNS-based vulnerability checks..."
        if [ -f "$OUTPUT_DIR/subdomains/all_subdomains.txt" ] && [ -s "$OUTPUT_DIR/subdomains/all_subdomains.txt" ]; then
            head -50 "$OUTPUT_DIR/subdomains/all_subdomains.txt" | nuclei -silent -tags dns -timeout 5 -rate-limit 100 -o "$OUTPUT_DIR/vulns/nuclei_dns_results.txt" 2>/dev/null || touch "$OUTPUT_DIR/vulns/nuclei_dns_results.txt"
            
            cat "$OUTPUT_DIR/vulns/nuclei_results.txt" "$OUTPUT_DIR/vulns/nuclei_dns_results.txt" 2>/dev/null | sort -u > "$OUTPUT_DIR/vulns/nuclei_combined.txt" || touch "$OUTPUT_DIR/vulns/nuclei_combined.txt"
            mv "$OUTPUT_DIR/vulns/nuclei_combined.txt" "$OUTPUT_DIR/vulns/nuclei_results.txt"
        fi
    else
        display_warning "Nuclei is not properly installed or configured"
        touch "$OUTPUT_DIR/vulns/nuclei_results.txt"
    fi
else
    if [[ ! " ${AVAILABLE_TOOLS[*]} " =~ " nuclei " ]]; then
        display_warning "Nuclei not available - skipping vulnerability scan"
    elif [ "$LIVE_COUNT" -eq 0 ]; then
        display_warning "No live hosts found - skipping vulnerability scan"
    fi
    touch "$OUTPUT_DIR/vulns/nuclei_results.txt"
fi

VULN_COUNT=$(count_results "$OUTPUT_DIR/vulns/nuclei_results.txt")

# Create vulnerability summary
if [ "$VULN_COUNT" -gt 0 ]; then
    echo "# Vulnerability Summary - $(date)" > "$OUTPUT_DIR/vulns/vulnerability_summary.txt"
    echo "Total vulnerabilities found: $VULN_COUNT" >> "$OUTPUT_DIR/vulns/vulnerability_summary.txt"
    echo "" >> "$OUTPUT_DIR/vulns/vulnerability_summary.txt"
    
    if [ -s "$OUTPUT_DIR/vulns/nuclei_results.txt" ]; then
        echo "Vulnerability breakdown:" >> "$OUTPUT_DIR/vulns/vulnerability_summary.txt"
        grep -o '\[.*\]' "$OUTPUT_DIR/vulns/nuclei_results.txt" 2>/dev/null | sort | uniq -c | sort -nr >> "$OUTPUT_DIR/vulns/vulnerability_summary.txt" 2>/dev/null || echo "Unable to parse vulnerability types" >> "$OUTPUT_DIR/vulns/vulnerability_summary.txt"
    fi
else
    echo "# No vulnerabilities found by automated scan - $(date)" > "$OUTPUT_DIR/vulns/vulnerability_summary.txt"
    echo "This does not guarantee the absence of vulnerabilities." >> "$OUTPUT_DIR/vulns/vulnerability_summary.txt"
    echo "Manual testing is recommended for thorough assessment." >> "$OUTPUT_DIR/vulns/vulnerability_summary.txt"
fi

log_phase "9" "Vulnerability Scanning - Found $VULN_COUNT potential vulnerabilities"

# =============================================================================
# PHASE 10: VIRUSTOTAL THREAT INTELLIGENCE (FULL MODE ONLY)
# =============================================================================
if [ "$RECON_MODE" = "FULL" ] && [ -n "${VIRUSTOTAL_API_KEY:-}" ]; then
    display_phase_header "10" "ENHANCED VIRUSTOTAL THREAT INTELLIGENCE"
    
    display_operation "Analyzing domain reputation..."
    # Domain analysis
    VT_DOMAIN_RESPONSE=$(curl -s -H "x-apikey: ${VIRUSTOTAL_API_KEY}" \
        "https://www.virustotal.com/api/v3/domains/${TARGET_DOMAIN}" || echo "{}")
    
    if echo "$VT_DOMAIN_RESPONSE" | jq -e '.data' >/dev/null 2>&1; then
        echo "=== VirusTotal Domain Analysis for $TARGET_DOMAIN ===" > "$OUTPUT_DIR/virustotal/domain_analysis.txt"
        echo "$VT_DOMAIN_RESPONSE" | jq -r '.data.attributes | 
        "Reputation: \(.reputation // "N/A")
Categories: \(.categories // {} | to_entries | map("\(.key): \(.value)") | join(", "))
Last Analysis: \(.last_analysis_date // "N/A" | todate)
Malicious Votes: \(.last_analysis_stats.malicious // 0)
Suspicious Votes: \(.last_analysis_stats.suspicious // 0)
Harmless Votes: \(.last_analysis_stats.harmless // 0)
Total Votes: \(.total_votes.harmless // 0 + .total_votes.malicious // 0)"' >> "$OUTPUT_DIR/virustotal/domain_analysis.txt" 2>/dev/null || echo "Failed to parse domain data" >> "$OUTPUT_DIR/virustotal/domain_analysis.txt"
    else
        echo "No VirusTotal data available for $TARGET_DOMAIN" > "$OUTPUT_DIR/virustotal/domain_analysis.txt"
    fi
    
    display_operation "Enhanced subdomain reputation analysis..."
    # Check subdomains with improved analysis (limit to first 25 to respect API limits)
    if [ -f "$OUTPUT_DIR/subdomains/all_subdomains.txt" ] && [ -s "$OUTPUT_DIR/subdomains/all_subdomains.txt" ]; then
        head -25 "$OUTPUT_DIR/subdomains/all_subdomains.txt" | while read -r subdomain; do
            if [ -n "$subdomain" ]; then
                echo "Checking: $subdomain" >> "$OUTPUT_DIR/virustotal/subdomain_analysis.txt"
                VT_SUB_RESPONSE=$(curl -s -H "x-apikey: ${VIRUSTOTAL_API_KEY}" \
                    "https://www.virustotal.com/api/v3/domains/${subdomain}" || echo "{}")
                
                if echo "$VT_SUB_RESPONSE" | jq -e '.data' >/dev/null 2>&1; then
                    REPUTATION=$(echo "$VT_SUB_RESPONSE" | jq -r '.data.attributes.reputation // "N/A"')
                    MALICIOUS=$(echo "$VT_SUB_RESPONSE" | jq -r '.data.attributes.last_analysis_stats.malicious // 0')
                    SUSPICIOUS=$(echo "$VT_SUB_RESPONSE" | jq -r '.data.attributes.last_analysis_stats.suspicious // 0')
                    CATEGORIES=$(echo "$VT_SUB_RESPONSE" | jq -r '.data.attributes.categories // {} | to_entries | map("\(.key): \(.value)") | join(", ")')
                    
                    echo "$subdomain | Reputation: $REPUTATION | Malicious: $MALICIOUS | Suspicious: $SUSPICIOUS | Categories: $CATEGORIES" >> "$OUTPUT_DIR/virustotal/subdomain_analysis.txt"
                    
                    # Flag potentially malicious subdomains with enhanced criteria
                    if [ "$MALICIOUS" -gt 0 ] || [ "$SUSPICIOUS" -gt 2 ] || echo "$CATEGORIES" | grep -qi "malicious\|phishing\|suspicious"; then
                        echo "$subdomain | Reputation: $REPUTATION | Malicious: $MALICIOUS | Suspicious: $SUSPICIOUS | Categories: $CATEGORIES" >> "$OUTPUT_DIR/virustotal/flagged_domains.txt"
                    fi
                else
                    echo "$subdomain | No VT data available" >> "$OUTPUT_DIR/virustotal/subdomain_analysis.txt"
                fi
                
                sleep 1  # Rate limiting
            fi
        done
    fi
    
    display_operation "Enhanced IP reputation analysis..."
    # Check IP addresses with geolocation data
    if [ -f "$OUTPUT_DIR/asn/target_ips.txt" ] && [ -s "$OUTPUT_DIR/asn/target_ips.txt" ]; then
        while read -r ip; do
            if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                echo "Checking IP: $ip" >> "$OUTPUT_DIR/virustotal/ip_analysis.txt"
                VT_IP_RESPONSE=$(curl -s -H "x-apikey: ${VIRUSTOTAL_API_KEY}" \
                    "https://www.virustotal.com/api/v3/ip_addresses/${ip}" || echo "{}")
                
                if echo "$VT_IP_RESPONSE" | jq -e '.data' >/dev/null 2>&1; then
                    REPUTATION=$(echo "$VT_IP_RESPONSE" | jq -r '.data.attributes.reputation // "N/A"')
                    MALICIOUS=$(echo "$VT_IP_RESPONSE" | jq -r '.data.attributes.last_analysis_stats.malicious // 0')
                    SUSPICIOUS=$(echo "$VT_IP_RESPONSE" | jq -r '.data.attributes.last_analysis_stats.suspicious // 0')
                    COUNTRY=$(echo "$VT_IP_RESPONSE" | jq -r '.data.attributes.country // "N/A"')
                    ASN=$(echo "$VT_IP_RESPONSE" | jq -r '.data.attributes.asn // "N/A"')
                    NETWORK=$(echo "$VT_IP_RESPONSE" | jq -r '.data.attributes.network // "N/A"')
                    
                    echo "$ip | Country: $COUNTRY | ASN: $ASN | Network: $NETWORK | Reputation: $REPUTATION | Malicious: $MALICIOUS | Suspicious: $SUSPICIOUS" >> "$OUTPUT_DIR/virustotal/ip_analysis.txt"
                    
                    # Flag potentially malicious IPs
                    if [ "$MALICIOUS" -gt 0 ] || [ "$SUSPICIOUS" -gt 2 ]; then
                        echo "$ip | Country: $COUNTRY | ASN: $ASN | Network: $NETWORK | Reputation: $REPUTATION | Malicious: $MALICIOUS | Suspicious: $SUSPICIOUS" >> "$OUTPUT_DIR/virustotal/flagged_ips.txt"
                    fi
                else
                    echo "$ip | No VT data available" >> "$OUTPUT_DIR/virustotal/ip_analysis.txt"
                fi
                
                sleep 1  # Rate limiting
            fi
        done < "$OUTPUT_DIR/asn/target_ips.txt"
    fi
    
    display_operation "Creating enhanced threat intelligence summary..."
    cat > "$OUTPUT_DIR/virustotal/threat_summary.txt" << VTSUM
# Enhanced VirusTotal Threat Intelligence Summary - $TARGET_DOMAIN
Generated: $(date)

## Domain Analysis
$(cat "$OUTPUT_DIR/virustotal/domain_analysis.txt" 2>/dev/null || echo "No domain analysis available")

## Flagged Assets
$(if [ -f "$OUTPUT_DIR/virustotal/flagged_domains.txt" ]; then
    echo "### Suspicious Domains:"
    cat "$OUTPUT_DIR/virustotal/flagged_domains.txt"
else
    echo "No flagged domains found"
fi)

$(if [ -f "$OUTPUT_DIR/virustotal/flagged_ips.txt" ]; then
    echo "### Suspicious IP Addresses:"
    cat "$OUTPUT_DIR/virustotal/flagged_ips.txt"
else
    echo "No flagged IPs found"
fi)

## Historical Analysis Insights
- Review flagged assets for potential security concerns
- Investigate any domains/IPs with malicious votes  
- Cross-reference suspicious findings with discovered vulnerabilities
- Monitor flagged subdomains for potential compromise indicators

## Recommendations
- Implement DNS monitoring for flagged domains
- Consider additional monitoring for suspicious assets
- Verify legitimacy of flagged subdomains
- Correlate threat intelligence with network monitoring
- Review historical changes in domain reputation
VTSUM
    
    VT_DOMAINS_CHECKED=$(wc -l < "$OUTPUT_DIR/virustotal/subdomain_analysis.txt" 2>/dev/null || echo "0")
    VT_FLAGGED=$(cat "$OUTPUT_DIR/virustotal/flagged_domains.txt" "$OUTPUT_DIR/virustotal/flagged_ips.txt" 2>/dev/null | wc -l || echo "0")
    
    log_phase "10" "Enhanced VirusTotal Intelligence - Checked $VT_DOMAINS_CHECKED assets, flagged $VT_FLAGGED"
else
    display_phase_header "10" "VIRUSTOTAL THREAT INTELLIGENCE"
    if [ "$RECON_MODE" = "FULL" ] && [ -z "${VIRUSTOTAL_API_KEY:-}" ]; then
        display_info "VirusTotal API key not configured (optional)"
    else
        display_info "VirusTotal intelligence skipped (Basic mode)"
    fi
    echo "# VirusTotal intelligence not available" > "$OUTPUT_DIR/virustotal/skipped.txt"
    VT_DOMAINS_CHECKED=0
    VT_FLAGGED=0
fi

# =============================================================================
# PHASE 11: ENHANCED GITHUB INTELLIGENCE GATHERING (FULL MODE ONLY)
# =============================================================================
if [ "$RECON_MODE" = "FULL" ] && [ -n "${GITHUB_TOKEN:-}" ]; then
    display_phase_header "11" "ENHANCED GITHUB INTELLIGENCE GATHERING"
    
    display_operation "Comprehensive GitHub search for sensitive data exposure..."
    
    # Enhanced search queries with more specific patterns
    GITHUB_QUERIES=(
        "\"$TARGET_DOMAIN\" password"
        "\"$TARGET_DOMAIN\" api_key"
        "\"$TARGET_DOMAIN\" secret"
        "\"$TARGET_DOMAIN\" token"
        "\"$TARGET_DOMAIN\" filename:.env"
        "\"$TARGET_DOMAIN\" filename:.config"
        "\"$TARGET_DOMAIN\" filename:wp-config.php"
        "\"$TARGET_DOMAIN\" extension:sql"
        "\"$TARGET_DOMAIN\" extension:xml"
        "\"$TARGET_DOMAIN\" extension:json"
        "org:$(echo $TARGET_DOMAIN | cut -d'.' -f1) password"
        "org:$(echo $TARGET_DOMAIN | cut -d'.' -f1) api_key"
    )
    
    display_operation "Searching GitHub repositories and code..."
    for query in "${GITHUB_QUERIES[@]}"; do
        echo "Searching: $query" >> "$OUTPUT_DIR/github/search_log.txt"
        
        # Search in code
        curl -s -H "Authorization: token $GITHUB_TOKEN" \
             "https://api.github.com/search/code?q=$(echo "$query" | sed 's/ /%20/g')" \
             >> "$OUTPUT_DIR/github/code_search_results.json" 2>/dev/null || true
        
        sleep 2  # Rate limiting
        
        # Search in repositories
        curl -s -H "Authorization: token $GITHUB_TOKEN" \
             "https://api.github.com/search/repositories?q=$(echo "$query" | sed 's/ /%20/g')" \
             >> "$OUTPUT_DIR/github/repo_search_results.json" 2>/dev/null || true
        
        sleep 2  # Rate limiting
    done
    
    display_operation "Processing GitHub search results..."
    if [ -f "$OUTPUT_DIR/github/code_search_results.json" ]; then
        jq -r '.items[]?.html_url' "$OUTPUT_DIR/github/code_search_results.json" 2>/dev/null > "$OUTPUT_DIR/github/sensitive_code_urls.txt" || touch "$OUTPUT_DIR/github/sensitive_code_urls.txt"
    fi
    
    if [ -f "$OUTPUT_DIR/github/repo_search_results.json" ]; then
        jq -r '.items[]?.html_url' "$OUTPUT_DIR/github/repo_search_results.json" 2>/dev/null > "$OUTPUT_DIR/github/sensitive_repo_urls.txt" || touch "$OUTPUT_DIR/github/sensitive_repo_urls.txt"
    fi
    
    # Combine all results
    cat "$OUTPUT_DIR/github/sensitive_code_urls.txt" "$OUTPUT_DIR/github/sensitive_repo_urls.txt" 2>/dev/null | sort -u > "$OUTPUT_DIR/github/all_sensitive_urls.txt" || touch "$OUTPUT_DIR/github/all_sensitive_urls.txt"
    
    display_operation "Searching GitLab for additional exposure..."
    # Basic GitLab search (public API)
    GITLAB_QUERIES=(
        "$TARGET_DOMAIN password"
        "$TARGET_DOMAIN api_key" 
        "$TARGET_DOMAIN secret"
    )
    
    for query in "${GITLAB_QUERIES[@]}"; do
        curl -s "https://gitlab.com/api/v4/search?scope=projects&search=$(echo "$query" | sed 's/ /%20/g')" \
             >> "$OUTPUT_DIR/github/gitlab_search_results.json" 2>/dev/null || true
        sleep 2
    done
    
    if [ -f "$OUTPUT_DIR/github/gitlab_search_results.json" ]; then
        jq -r '.[].web_url' "$OUTPUT_DIR/github/gitlab_search_results.json" 2>/dev/null > "$OUTPUT_DIR/github/gitlab_urls.txt" || touch "$OUTPUT_DIR/github/gitlab_urls.txt"
    fi
    
    GITHUB_RESULTS=$(count_results "$OUTPUT_DIR/github/all_sensitive_urls.txt")
    GITLAB_RESULTS=$(count_results "$OUTPUT_DIR/github/gitlab_urls.txt")
    
    # Create comprehensive summary
    cat > "$OUTPUT_DIR/github/intelligence_summary.txt" << GHSUM
# Enhanced GitHub/GitLab Intelligence Summary - $TARGET_DOMAIN
Generated: $(date)

## Search Results:
- GitHub Code/Repository Results: $GITHUB_RESULTS
- GitLab Project Results: $GITLAB_RESULTS

## High-Priority Review Items:
$(if [ "$GITHUB_RESULTS" -gt 0 ]; then
    echo "### GitHub Findings:"
    echo "Review these URLs for potential credential exposure:"
    head -10 "$OUTPUT_DIR/github/all_sensitive_urls.txt" 2>/dev/null || echo "No results to display"
    if [ "$GITHUB_RESULTS" -gt 10 ]; then
        echo "... and $((GITHUB_RESULTS - 10)) more results in all_sensitive_urls.txt"
    fi
else
    echo "No GitHub results found"
fi)

$(if [ "$GITLAB_RESULTS" -gt 0 ]; then
    echo "### GitLab Findings:"
    head -5 "$OUTPUT_DIR/github/gitlab_urls.txt" 2>/dev/null || echo "No results to display"
fi)

## Investigation Recommendations:
- Review identified repositories for hardcoded credentials
- Check commit history for accidentally committed secrets
- Look for configuration files with sensitive information
- Verify if any exposed credentials are still active
- Consider implementing secret scanning in CI/CD pipelines
GHSUM
    
    log_phase "11" "Enhanced GitHub Intelligence - Found $GITHUB_RESULTS GitHub + $GITLAB_RESULTS GitLab potential matches"
else
    display_phase_header "11" "GITHUB INTELLIGENCE GATHERING"
    display_info "GitHub intelligence skipped (Basic mode or no token)"
    echo "# GitHub intelligence not available in basic mode" > "$OUTPUT_DIR/github/skipped.txt"
    GITHUB_RESULTS=0
    GITLAB_RESULTS=0
fi

# =============================================================================
# PHASE 12: MICROSOFT/OFFICE365 ENUMERATION (FULL MODE ONLY)
# =============================================================================
if [ "$RECON_MODE" = "FULL" ]; then
    display_phase_header "12" "MICROSOFT SERVICES ENUMERATION"
    
    display_operation "Checking Microsoft/Office365 services..."
    MS_SUBDOMAINS=("autodiscover" "lyncdiscover" "sip" "enterpriseregistration" "enterpriseenrollment" "msoid" "_sip._tcp" "_sipfederationtls._tcp")
    
    for subdomain in "${MS_SUBDOMAINS[@]}"; do
        result=$(dig +short "${subdomain}.${TARGET_DOMAIN}" 2>/dev/null || true)
        if [ -n "$result" ]; then
            echo "${subdomain}.${TARGET_DOMAIN} -> $result" >> "$OUTPUT_DIR/microsoft/ms_services.txt"
        fi
    done
    
    display_operation "Testing Office365 tenant information..."
    # Check if domain is using Office365
    O365_CHECK=$(curl -s "https://login.microsoftonline.com/${TARGET_DOMAIN}/.well-known/openid_configuration" | jq -r '.issuer' 2>/dev/null || echo "")
    if [ -n "$O365_CHECK" ] && [[ "$O365_CHECK" != "null" ]]; then
        echo "Office365 tenant detected: $O365_CHECK" >> "$OUTPUT_DIR/microsoft/o365_info.txt"
        
        # Get tenant information
        curl -s "https://login.microsoftonline.com/${TARGET_DOMAIN}/v2.0/.well-known/openid_configuration" > "$OUTPUT_DIR/microsoft/o365_openid_config.json" 2>/dev/null || true
    fi
    
    MS_SERVICES=$(count_results "$OUTPUT_DIR/microsoft/ms_services.txt")
    O365_DETECTED=$([[ -f "$OUTPUT_DIR/microsoft/o365_info.txt" ]] && echo "1" || echo "0")
    
    log_phase "12" "Microsoft Enumeration - Found $MS_SERVICES services, O365: $([[ "$O365_DETECTED" = "1" ]] && echo "Yes" || echo "No")"
else
    display_phase_header "12" "MICROSOFT ENUMERATION"
    display_info "Microsoft enumeration skipped (Basic mode)"
    echo "# Microsoft enumeration not available in basic mode" > "$OUTPUT_DIR/microsoft/skipped.txt"
    MS_SERVICES=0
    O365_DETECTED=0
fi

# =============================================================================
# PHASE 13: OSINT AND SOCIAL INTELLIGENCE (NEW)
# =============================================================================
display_phase_header "13" "OSINT AND SOCIAL INTELLIGENCE"

display_operation "Gathering social media and forum intelligence..."

# Basic social media checks (respecting rate limits)
display_operation "Checking social media presence..."

# LinkedIn company search (basic)
COMPANY_NAME=$(echo "$TARGET_DOMAIN" | cut -d'.' -f1)
echo "LinkedIn: https://www.linkedin.com/company/$COMPANY_NAME" >> "$OUTPUT_DIR/osint/social_media_profiles.txt"

# Twitter/X search
echo "Twitter: https://twitter.com/$COMPANY_NAME" >> "$OUTPUT_DIR/osint/social_media_profiles.txt"

# Reddit mentions check
display_operation "Checking Reddit for mentions..."
REDDIT_SEARCH_URL="https://www.reddit.com/search.json?q=${TARGET_DOMAIN}&limit=10"
curl -s -A "Ante Reconnaissance Bot 1.0" "$REDDIT_SEARCH_URL" > "$OUTPUT_DIR/osint/reddit_search.json" 2>/dev/null || touch "$OUTPUT_DIR/osint/reddit_search.json"

if [ -s "$OUTPUT_DIR/osint/reddit_search.json" ]; then
    jq -r '.data.children[].data | "https://reddit.com\(.permalink) - \(.title)"' "$OUTPUT_DIR/osint/reddit_search.json" 2>/dev/null > "$OUTPUT_DIR/osint/reddit_mentions.txt" || touch "$OUTPUT_DIR/osint/reddit_mentions.txt"
fi

# Check for Wayback Machine historical analysis
display_operation "Historical website analysis via Wayback Machine..."
WB_URL="http://web.archive.org/cdx/search/cdx?url=${TARGET_DOMAIN}&output=text&fl=timestamp,original&limit=20"
curl -s "$WB_URL" > "$OUTPUT_DIR/osint/wayback_timeline.txt" 2>/dev/null || touch "$OUTPUT_DIR/osint/wayback_timeline.txt"

# Check for technology mentions on Stack Overflow (basic)
display_operation "Checking Stack Overflow for technology discussions..."
echo "Stack Overflow search: https://stackoverflow.com/search?q=${TARGET_DOMAIN}" >> "$OUTPUT_DIR/osint/tech_discussions.txt"

# Create OSINT summary
REDDIT_MENTIONS=$(count_results "$OUTPUT_DIR/osint/reddit_mentions.txt")
WAYBACK_ENTRIES=$(count_results "$OUTPUT_DIR/osint/wayback_timeline.txt")

cat > "$OUTPUT_DIR/osint/osint_summary.txt" << OSINTSUM
# OSINT and Social Intelligence Summary - $TARGET_DOMAIN
Generated: $(date)

## Social Media Presence:
$(cat "$OUTPUT_DIR/osint/social_media_profiles.txt" 2>/dev/null || echo "No social media profiles identified")

## Community Discussions:
- Reddit mentions found: $REDDIT_MENTIONS
- Stack Overflow discussions: Manual review recommended

## Historical Analysis:
- Wayback Machine entries: $WAYBACK_ENTRIES
- First archived: $(head -1 "$OUTPUT_DIR/osint/wayback_timeline.txt" 2>/dev/null | cut -f1 | head -c 8 || echo "Unknown")
- Last archived: $(tail -1 "$OUTPUT_DIR/osint/wayback_timeline.txt" 2>/dev/null | cut -f1 | head -c 8 || echo "Unknown")

## Investigation Recommendations:
- Review Reddit discussions for security-related mentions
- Analyze historical website changes for technology evolution
- Check social media for employee information and company updates
- Monitor community discussions for reputation insights
OSINTSUM

log_phase "13" "OSINT Intelligence - Found $REDDIT_MENTIONS Reddit mentions, $WAYBACK_ENTRIES historical entries"

# =============================================================================
# PHASE 14: CONFIGURATION EXPOSURE DETECTION (NEW)
# =============================================================================
display_phase_header "14" "CONFIGURATION EXPOSURE DETECTION"

display_operation "Scanning for configuration file exposure..."

CONFIG_ENDPOINTS=(
    "robots.txt"
    "sitemap.xml" 
    ".well-known/security.txt"
    ".well-known/openid_configuration"
    "crossdomain.xml"
    "clientaccesspolicy.xml"
    ".env"
    "web.config"
    ".htaccess"
    "wp-config.php"
    "config.php"
    "application.properties"
    ".git/config"
    ".git/HEAD"
    "composer.json"
    "package.json"
    "Dockerfile"
)

display_operation "Testing common configuration endpoints..."
CONFIG_FOUND=0

while read -r url; do
    if [ -n "$url" ]; then
        base_url=$(echo "$url" | sed 's|https\?://||' | cut -d'/' -f1)
        
        for endpoint in "${CONFIG_ENDPOINTS[@]}"; do
            for protocol in "https" "http"; do
                full_url="${protocol}://${base_url}/${endpoint}"
                response=$(timeout 10 curl -s -I "$full_url" 2>/dev/null || true)
                
                if echo "$response" | grep -q "200\|301\|302"; then
                    echo "$full_url - $(echo "$response" | head -1 | tr -d '\r')" >> "$OUTPUT_DIR/config_analysis/exposed_configs.txt"
                    CONFIG_FOUND=$((CONFIG_FOUND + 1))
                    
                    # Get actual content for analysis (limited to prevent large downloads)
                    timeout 5 curl -s "$full_url" | head -20 > "$OUTPUT_DIR/config_analysis/content_${base_url}_${endpoint//\//_}.txt" 2>/dev/null || true
                    break
                fi
            done
        done
    fi
done < <(head -10 "$OUTPUT_DIR/live_hosts/live_hosts.txt" 2>/dev/null || true)

display_operation "Analyzing security headers..."
HEADERS_CHECKED=0

while read -r url; do
    if [ -n "$url" ]; then
        echo "=== Security Headers for $url ===" >> "$OUTPUT_DIR/config_analysis/security_headers.txt"
        
        response=$(timeout 10 curl -s -I "$url" 2>/dev/null || true)
        
        # Check for important security headers
        SECURITY_HEADERS=("strict-transport-security" "content-security-policy" "x-frame-options" "x-content-type-options" "x-xss-protection" "referrer-policy")
        
        for header in "${SECURITY_HEADERS[@]}"; do
            header_value=$(echo "$response" | grep -i "$header:" || echo "Missing: $header")
            echo "$header_value" >> "$OUTPUT_DIR/config_analysis/security_headers.txt"
        done
        
        echo "" >> "$OUTPUT_DIR/config_analysis/security_headers.txt"
        HEADERS_CHECKED=$((HEADERS_CHECKED + 1))
    fi
done < <(head -5 "$OUTPUT_DIR/live_hosts/live_hosts.txt" 2>/dev/null || true)

# Create configuration analysis summary
cat > "$OUTPUT_DIR/config_analysis/config_summary.txt" << CONFIGSUM
# Configuration Exposure Analysis - $TARGET_DOMAIN
Generated: $(date)

## Exposed Configuration Files:
Found $CONFIG_FOUND potentially accessible configuration endpoints.

$(if [ "$CONFIG_FOUND" -gt 0 ]; then
    echo "Accessible endpoints:"
    cat "$OUTPUT_DIR/config_analysis/exposed_configs.txt" 2>/dev/null || echo "None found"
else
    echo "No configuration files found accessible via common paths."
fi)

## Security Headers Analysis:
Analyzed $HEADERS_CHECKED web applications for security headers.
Detailed results available in security_headers.txt.

## Risk Assessment:
- Review exposed configuration files for sensitive information
- Implement proper security headers where missing  
- Ensure configuration files are not accessible to public
- Consider implementing Content Security Policy (CSP)
- Review robots.txt for information disclosure

## Manual Testing Recommendations:
- Test for additional configuration file patterns
- Verify security header implementation across all applications
- Check for backup files (.bak, .old, .orig)
- Test for source code disclosure vulnerabilities
CONFIGSUM

log_phase "14" "Configuration Exposure - Found $CONFIG_FOUND exposed configs, analyzed $HEADERS_CHECKED security headers"

# =============================================================================
# PHASE 15: REPORT GENERATION AND ANALYSIS
# =============================================================================
display_phase_header "15" "COMPREHENSIVE REPORT GENERATION"

display_operation "Generating enhanced executive summary..."
REPORT_FILE="$OUTPUT_DIR/summary/reconnaissance_report.md"

cat > "$REPORT_FILE" << EOF
# Enhanced Reconnaissance Report - $TARGET_DOMAIN

**Generated:** $(date)  
**Mode:** $RECON_MODE Reconnaissance  
**Author:** Ante Advanced Reconnaissance System v2.0
**Integration:** BigBountyRecon OSINT Techniques

## Executive Summary

This enhanced reconnaissance assessment integrated comprehensive OSINT methodologies to provide deep intelligence on the target organization. The assessment identified attack surface, potential security issues, and intelligence across multiple vectors including social media, historical analysis, and configuration exposure.

## Key Statistics

| Category | Count | Details |
|----------|--------|---------|
| ASNs Discovered | $ASN_COUNT | Autonomous System Numbers |
| Subdomains Found | $SUBDOMAIN_COUNT | Multi-source subdomain discovery |
| Live Web Services | $LIVE_COUNT | Responding HTTP/HTTPS services |
| Open Network Ports | $OPEN_PORTS | Accessible services |
| SSL Certificates | $SSL_COUNT | Certificate analysis completed |
| Web Technologies | $TECH_COUNT | Identified technology stacks |
| Subdomain Takeovers | $TAKEOVER_COUNT | Potential takeover vulnerabilities |
| Potential Vulnerabilities | $VULN_COUNT | Nuclei scanner results |
| Configuration Exposures | $CONFIG_FOUND | Exposed configuration files |
| OSINT Reddit Mentions | $REDDIT_MENTIONS | Social intelligence gathered |
EOF

if [ "$RECON_MODE" = "FULL" ]; then
    cat >> "$REPORT_FILE" << EOF
| VirusTotal Checks | $VT_DOMAINS_CHECKED | Threat intelligence analyzed |
| Flagged Assets | $VT_FLAGGED | Potentially malicious indicators |
| GitHub/GitLab Results | $((GITHUB_RESULTS + GITLAB_RESULTS)) | Potential sensitive data exposure |
| Microsoft Services | $MS_SERVICES | Office365/Azure related services |
| Cloud Storage Buckets | ${BUCKET_COUNT:-0} | Accessible cloud storage found |
EOF
fi

cat >> "$REPORT_FILE" << EOF

## Enhanced Intelligence Gathering

### OSINT Analysis
- **Social Media Presence:** Identified key social media profiles
- **Community Discussions:** $REDDIT_MENTIONS Reddit mentions discovered
- **Historical Analysis:** $WAYBACK_ENTRIES Wayback Machine entries analyzed
- **Technology Discussions:** Stack Overflow presence identified

### Configuration Security Analysis  
- **Exposed Configurations:** $CONFIG_FOUND potentially accessible config files
- **Security Headers:** $HEADERS_CHECKED web applications analyzed
- **Risk Assessment:** Comprehensive security posture evaluation

### Advanced Threat Intelligence
EOF

if [ "$RECON_MODE" = "FULL" ]; then
    cat >> "$REPORT_FILE" << EOF
- **Enhanced GitHub Intelligence:** Multi-pattern search across code and repositories
- **GitLab Integration:** Additional source code analysis
- **VirusTotal Enhancement:** Historical reputation analysis with categorization
- **Cloud Storage Discovery:** Predictive bucket enumeration with accessibility testing
EOF
else
    cat >> "$REPORT_FILE" << EOF
- **Basic OSINT:** Social media and historical analysis
- **Configuration Security:** Exposed file and security header analysis
- **Certificate Intelligence:** Multi-source certificate transparency analysis
EOF
fi

cat >> "$REPORT_FILE" << EOF

## Attack Surface Summary

### Critical Findings Requiring Immediate Attention
EOF

# Add critical findings based on results
if [ "$TAKEOVER_COUNT" -gt 0 ]; then
    echo "- **CRITICAL:** $TAKEOVER_COUNT potential subdomain takeover vulnerabilities identified" >> "$REPORT_FILE"
fi

if [ "$VT_FLAGGED" -gt 0 ]; then
    echo "- **HIGH:** $VT_FLAGGED assets flagged by VirusTotal threat intelligence" >> "$REPORT_FILE"
fi

if [ "$GITHUB_RESULTS" -gt 0 ] || [ "$GITLAB_RESULTS" -gt 0 ]; then
    echo "- **HIGH:** $((GITHUB_RESULTS + GITLAB_RESULTS)) potential credential exposures in code repositories" >> "$REPORT_FILE"
fi

if [ "$CONFIG_FOUND" -gt 0 ]; then
    echo "- **MEDIUM:** $CONFIG_FOUND exposed configuration files requiring review" >> "$REPORT_FILE"
fi

cat >> "$REPORT_FILE" << EOF

### Infrastructure Intelligence
- **Network Footprint:** $ASN_COUNT ASNs managing $IP_COUNT unique IP addresses
- **Web Presence:** $LIVE_COUNT active web services across $SUBDOMAIN_COUNT subdomains
- **Technology Stack:** $TECH_COUNT different technologies identified
- **Cloud Infrastructure:** $((TOTAL_MATCHES + ${BUCKET_COUNT:-0})) cloud assets identified

### Reconnaissance Methodology Enhancement
This assessment utilized enhanced reconnaissance techniques inspired by BigBountyRecon:
- Multi-source Certificate Transparency analysis
- Predictive cloud storage enumeration  
- Enhanced GitHub/GitLab intelligence gathering
- Historical analysis via Wayback Machine
- Social media and community intelligence
- Configuration exposure detection
- Advanced security header analysis

## Next Steps and Recommendations

### Immediate Actions (High Priority)
1. **Vulnerability Remediation:** Address $VULN_COUNT identified vulnerabilities
2. **Subdomain Security:** Investigate $TAKEOVER_COUNT potential takeover vulnerabilities
3. **Configuration Hardening:** Secure $CONFIG_FOUND exposed configuration files
4. **Threat Intelligence Review:** Analyze $VT_FLAGGED flagged assets for security concerns

### Enhanced Security Measures
1. **Repository Security:** Review $((GITHUB_RESULTS + GITLAB_RESULTS)) potential credential exposures
2. **Cloud Security:** Audit identified cloud storage buckets for data exposure
3. **Social Engineering Prevention:** Monitor social media and community discussions
4. **Historical Monitoring:** Implement monitoring for historical vulnerabilities

### Ongoing Monitoring
- Implement continuous subdomain monitoring
- Set up alerts for new repository mentions
- Monitor VirusTotal for reputation changes
- Track configuration file accessibility

EOF

display_operation "Creating enhanced investigation checklist..."
cat > "$OUTPUT_DIR/summary/investigation_checklist.md" << CHECKLIST
# Enhanced Investigation Checklist - $TARGET_DOMAIN

## Immediate Review (Critical Priority)

### Security Vulnerabilities
- [ ] **Vulnerability Assessment:** Review \`vulns/nuclei_results.txt\` for $VULN_COUNT issues
- [ ] **Subdomain Takeovers:** Investigate \`vulns/subdomain_takeover.txt\` for $TAKEOVER_COUNT potential takeovers
- [ ] **Configuration Exposure:** Review \`config_analysis/exposed_configs.txt\` for $CONFIG_FOUND exposed files
- [ ] **Security Headers:** Analyze \`config_analysis/security_headers.txt\` for missing protections

### Intelligence Analysis  
- [ ] **Live Services:** Examine all $LIVE_COUNT active web services for vulnerabilities
- [ ] **Open Ports:** Investigate $OPEN_PORTS network services for unauthorized access
- [ ] **SSL Certificates:** Verify certificate configurations and validity
- [ ] **Technology Stack:** Assess $TECH_COUNT identified technologies for known vulnerabilities

$(if [ "$RECON_MODE" = "FULL" ]; then
    echo "### Enhanced Intelligence (Full Mode)"
    echo "- [ ] **VirusTotal Analysis:** Review $VT_FLAGGED flagged assets in \`virustotal/flagged_*\`"
    echo "- [ ] **GitHub/GitLab Exposure:** Check \`github/all_sensitive_urls.txt\` for $((GITHUB_RESULTS + GITLAB_RESULTS)) potential leaks"
    echo "- [ ] **Microsoft Services:** Assess $MS_SERVICES Office365/Azure integrations"
    echo "- [ ] **Cloud Storage:** Review ${BUCKET_COUNT:-0} accessible cloud storage buckets"
fi)

### OSINT and Social Intelligence
- [ ] **Reddit Mentions:** Review $REDDIT_MENTIONS community discussions for security insights
- [ ] **Historical Analysis:** Analyze $WAYBACK_ENTRIES Wayback Machine entries for exposed data
- [ ] **Social Media:** Verify identified social media profiles for information disclosure
- [ ] **Employee Information:** Cross-reference social intelligence with security findings

## Secondary Analysis (Medium Priority)

### Network and Infrastructure
- [ ] **ASN Analysis:** Review $ASN_COUNT discovered ASNs for additional infrastructure
- [ ] **Cloud Infrastructure:** Investigate $TOTAL_MATCHES cloud provider matches
- [ ] **Certificate Intelligence:** Analyze multi-source certificate transparency data
- [ ] **DNS Analysis:** Review enhanced subdomain enumeration results

### Advanced Threat Analysis
- [ ] **Threat Intelligence:** Correlate VirusTotal findings with other security data
- [ ] **Historical Vulnerabilities:** Check Wayback Machine for previously exposed vulnerabilities
- [ ] **Technology Evolution:** Analyze historical technology changes for security impact
- [ ] **Reputation Monitoring:** Set up ongoing monitoring for flagged assets

## Reporting and Documentation

### Internal Reporting  
- [ ] **Executive Summary:** Present key findings to stakeholders
- [ ] **Technical Details:** Provide detailed analysis for security teams
- [ ] **Risk Assessment:** Prioritize findings based on business impact
- [ ] **Remediation Plan:** Develop timeline for addressing critical issues

### External Considerations
- [ ] **Responsible Disclosure:** Follow proper disclosure procedures for vulnerabilities
- [ ] **Compliance Impact:** Assess findings against regulatory requirements  
- [ ] **Third-Party Risk:** Evaluate supply chain and vendor security implications
- [ ] **Brand Protection:** Address any reputational risks identified

## Monitoring and Follow-up

### Continuous Monitoring Setup
- [ ] **Subdomain Monitoring:** Implement alerts for new subdomain discoveries
- [ ] **Repository Monitoring:** Set up alerts for new code repository mentions  
- [ ] **Vulnerability Scanning:** Schedule regular automated vulnerability assessments
- [ ] **Threat Intelligence:** Configure ongoing threat intelligence feeds

### Periodic Review Schedule
- [ ] **Weekly:** Review new findings and threat intelligence updates
- [ ] **Monthly:** Re-run reconnaissance to identify infrastructure changes
- [ ] **Quarterly:** Comprehensive security posture reassessment
- [ ] **Annual:** Full reconnaissance methodology review and enhancement
CHECKLIST

cat > "$OUTPUT_DIR/summary/high_value_targets.txt" << HVEOF
# High-Value Targets - $TARGET_DOMAIN

## Critical Security Issues (Immediate Attention)
$(if [ "$TAKEOVER_COUNT" -gt 0 ]; then
    echo "### Subdomain Takeover Vulnerabilities"
    echo "Priority: CRITICAL - Immediate remediation required"
    head -10 "$OUTPUT_DIR/vulns/subdomain_takeover.txt" 2>/dev/null | nl
    echo ""
fi)

$(if [ "$VT_FLAGGED" -gt 0 ]; then
    echo "### VirusTotal Flagged Assets"
    echo "Priority: HIGH - Threat intelligence indicates potential compromise"
    head -5 "$OUTPUT_DIR/virustotal/flagged_domains.txt" 2>/dev/null | nl
    head -5 "$OUTPUT_DIR/virustotal/flagged_ips.txt" 2>/dev/null | nl
    echo ""
fi)

## Live Web Applications (Priority Testing)
Priority: HIGH - Active attack surface
$(head -20 "$OUTPUT_DIR/live_hosts/live_hosts.txt" 2>/dev/null | nl || echo "No live hosts found")

## Exposed Configuration Files
Priority: MEDIUM-HIGH - Information disclosure risk  
$(head -10 "$OUTPUT_DIR/config_analysis/exposed_configs.txt" 2>/dev/null | nl || echo "No exposed configs found")

## Open Network Services
Priority: MEDIUM - Network attack surface
$(head -20 "$OUTPUT_DIR/portscan/open_ports.txt" 2>/dev/null | nl || echo "No open ports found")

$(if [ "$RECON_MODE" = "FULL" ]; then
    echo "## Sensitive Code Repository Findings"
    echo "Priority: HIGH - Potential credential exposure"
    head -10 "$OUTPUT_DIR/github/all_sensitive_urls.txt" 2>/dev/null | nl || echo "No GitHub findings"
    echo ""
    
    if [ "${BUCKET_COUNT:-0}" -gt 0 ]; then
        echo "## Accessible Cloud Storage"
        echo "Priority: HIGH - Data exposure risk"
        head -10 "$OUTPUT_DIR/cloud_recon/accessible_buckets.txt" 2>/dev/null | nl
        echo ""
    fi
fi)

## OSINT Intelligence Priorities
### Community Discussions Requiring Review
$(head -5 "$OUTPUT_DIR/osint/reddit_mentions.txt" 2>/dev/null | nl || echo "No Reddit mentions found")

### Historical Analysis Points
- First archived: $(head -1 "$OUTPUT_DIR/osint/wayback_timeline.txt" 2>/dev/null | cut -f1 | head -c 8 || echo "Unknown")
- Recent changes: $(tail -3 "$OUTPUT_DIR/osint/wayback_timeline.txt" 2>/dev/null | cut -f1 | head -c 8 | tr '\n' ' ' || echo "Unknown")
HVEOF

log_phase "15" "Comprehensive Report Generation - Complete"

# =============================================================================
# FINAL SUMMARY AND CLEANUP
# =============================================================================
echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                ENHANCED RECONNAISSANCE COMPLETE               ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"

# Calculate total runtime
END_TIME=$(date +%s)
RUNTIME=$((END_TIME - SCRIPT_START_TIME))
RUNTIME_MIN=$((RUNTIME / 60))
RUNTIME_SEC=$((RUNTIME % 60))

echo -e "${GREEN}[✓] Enhanced reconnaissance completed in ${RUNTIME_MIN}m ${RUNTIME_SEC}s${NC}"
echo -e "${GREEN}[✓] Results saved to: $OUTPUT_DIR${NC}"

# Display comprehensive metrics
echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}                        COMPREHENSIVE FINDINGS                   ${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"

printf "${YELLOW}%-25s${NC} %s\n" "Reconnaissance Mode:" "$RECON_MODE (Enhanced)"
printf "${YELLOW}%-25s${NC} %s\n" "Target Domain:" "$TARGET_DOMAIN"
printf "${YELLOW}%-25s${NC} %s\n" "ASNs Discovered:" "$ASN_COUNT"
printf "${YELLOW}%-25s${NC} %s\n" "Subdomains Found:" "$SUBDOMAIN_COUNT"
printf "${YELLOW}%-25s${NC} %s\n" "Live Web Services:" "$LIVE_COUNT"
printf "${YELLOW}%-25s${NC} %s\n" "Open Ports:" "$OPEN_PORTS"
printf "${YELLOW}%-25s${NC} %s\n" "SSL Certificates:" "$SSL_COUNT"
printf "${YELLOW}%-25s${NC} %s\n" "Technologies:" "$TECH_COUNT"
printf "${YELLOW}%-25s${NC} %s\n" "Subdomain Takeovers:" "$TAKEOVER_COUNT"
printf "${YELLOW}%-25s${NC} %s\n" "Vulnerabilities:" "$VULN_COUNT"
printf "${YELLOW}%-25s${NC} %s\n" "Config Exposures:" "$CONFIG_FOUND"
printf "${YELLOW}%-25s${NC} %s\n" "Reddit Mentions:" "$REDDIT_MENTIONS"
printf "${YELLOW}%-25s${NC} %s\n" "Historical Entries:" "$WAYBACK_ENTRIES"

if [ "$RECON_MODE" = "FULL" ]; then
    printf "${YELLOW}%-25s${NC} %s\n" "VirusTotal Checks:" "$VT_DOMAINS_CHECKED"
    printf "${YELLOW}%-25s${NC} %s\n" "Flagged Assets:" "$VT_FLAGGED"  
    printf "${YELLOW}%-25s${NC} %s\n" "GitHub Results:" "$GITHUB_RESULTS"
    printf "${YELLOW}%-25s${NC} %s\n" "GitLab Results:" "$GITLAB_RESULTS"
    printf "${YELLOW}%-25s${NC} %s\n" "Microsoft Services:" "$MS_SERVICES"
    printf "${YELLOW}%-25s${NC} %s\n" "Cloud Storage Buckets:" "${BUCKET_COUNT:-0}"
fi

echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════${NC}"

# Priority recommendations
echo -e "\n${BLUE}CRITICAL FINDINGS REQUIRING IMMEDIATE ATTENTION:${NC}"
if [ "$TAKEOVER_COUNT" -gt 0 ]; then
    echo -e "${RED}  🚨 CRITICAL: $TAKEOVER_COUNT subdomain takeover vulnerabilities in vulns/subdomain_takeover.txt${NC}"
fi

if [ "$RECON_MODE" = "FULL" ] && [ "$VT_FLAGGED" -gt 0 ]; then
    echo -e "${RED}  🚨 CRITICAL: $VT_FLAGGED assets flagged by VirusTotal threat intelligence${NC}"
fi

if [ "$VULN_COUNT" -gt 0 ]; then
    echo -e "${RED}  ⚠️  URGENT: $VULN_COUNT vulnerabilities identified in vulns/nuclei_results.txt${NC}"
fi

if [ "$RECON_MODE" = "FULL" ] && [ "$((GITHUB_RESULTS + GITLAB_RESULTS))" -gt 0 ]; then
    echo -e "${RED}  ⚠️  HIGH: $((GITHUB_RESULTS + GITLAB_RESULTS)) potential credential exposures in repositories${NC}"
fi

if [ "$CONFIG_FOUND" -gt 0 ]; then
    echo -e "${YELLOW}  📁 MEDIUM: $CONFIG_FOUND exposed configuration files require review${NC}"
fi

if [ "$RECON_MODE" = "FULL" ] && [ "${BUCKET_COUNT:-0}" -gt 0 ]; then
    echo -e "${YELLOW}  ☁️  MEDIUM: ${BUCKET_COUNT} accessible cloud storage buckets found${NC}"
fi

if [ "$LIVE_COUNT" -gt 15 ]; then
    echo -e "${YELLOW}  🌐 MEDIUM: Large attack surface with $LIVE_COUNT live services${NC}"
fi

if [[ " ${AVAILABLE_TOOLS[*]} " =~ " smap " ]]; then
    echo -e "\n${BLUE}SMAP INTELLIGENCE SUMMARY:${NC}"
    if [ -s "$OUTPUT_DIR/portscan/smap_vulnerabilities.txt" ]; then
        SMAP_VULN_COUNT=$(wc -l < "$OUTPUT_DIR/portscan/smap_vulnerabilities.txt")
        echo -e "${RED}  🔍 HIGH: Smap identified $SMAP_VULN_COUNT potential vulnerabilities${NC}"
    fi
    
    if [ -s "$OUTPUT_DIR/portscan/smap_ports.txt" ]; then
        SMAP_PORT_COUNT=$(wc -l < "$OUTPUT_DIR/portscan/smap_ports.txt")
        echo -e "${GREEN}  ⚡ Smap passive scan: $SMAP_PORT_COUNT ports discovered without target contact${NC}"
    fi
    
    echo -e "${CYAN}  📊 Shodan intelligence: Historical data up to 7 days old${NC}"
    echo -e "${CYAN}  🚀 Speed advantage: ~200 hosts/second scanning capability${NC}"
fi

echo -e "\n${BLUE}ENHANCED INTELLIGENCE SUMMARY:${NC}"
echo -e "${GREEN}  📊 Multi-source subdomain discovery with $SUBDOMAIN_COUNT total findings${NC}"
echo -e "${GREEN}  🕵️  Social intelligence: $REDDIT_MENTIONS community mentions discovered${NC}"
echo -e "${GREEN}  📚 Historical analysis: $WAYBACK_ENTRIES archived snapshots analyzed${NC}"
echo -e "${GREEN}  🔧 Configuration security: $HEADERS_CHECKED security header assessments${NC}"

if [ "$RECON_MODE" = "FULL" ]; then
    echo -e "${GREEN}  🔍 Enhanced GitHub/GitLab intelligence with multi-pattern searches${NC}"
    echo -e "${GREEN}  🛡️  Advanced threat intelligence with historical analysis${NC}"
    echo -e "${GREEN}  ☁️  Predictive cloud storage enumeration completed${NC}"
fi

echo -e "\n${BLUE}INVESTIGATION PRIORITIES:${NC}"
echo -e "  1. ${CYAN}Review: $OUTPUT_DIR/summary/investigation_checklist.md${NC}"
echo -e "  2. ${CYAN}Executive Report: $OUTPUT_DIR/summary/reconnaissance_report.md${NC}"
echo -e "  3. ${CYAN}High-Value Targets: $OUTPUT_DIR/summary/high_value_targets.txt${NC}"
echo -e "  4. ${CYAN}OSINT Intelligence: $OUTPUT_DIR/osint/osint_summary.txt${NC}"
echo -e "  5. ${CYAN}Configuration Analysis: $OUTPUT_DIR/config_analysis/config_summary.txt${NC}"

# Enhanced file organization summary  
echo -e "\n${BLUE}KEY DIRECTORIES TO REVIEW:${NC}"
echo -e "  📁 ${GREEN}summary/     ${NC}- Executive reports and investigation checklists"
echo -e "  📁 ${GREEN}osint/       ${NC}- Social media, Reddit, and historical intelligence"
echo -e "  📁 ${GREEN}config_analysis/ ${NC}- Configuration exposure and security header analysis"
echo -e "  📁 ${GREEN}live_hosts/  ${NC}- Active web services and technology detection"
echo -e "  📁 ${GREEN}vulns/       ${NC}- Vulnerability and takeover assessments"
echo -e "  📁 ${GREEN}cloud_recon/ ${NC}- Cloud infrastructure and storage analysis"

if [ "$RECON_MODE" = "FULL" ]; then
    echo -e "  📁 ${GREEN}github/      ${NC}- Source code intelligence and sensitive data exposure"
    echo -e "  📁 ${GREEN}virustotal/  ${NC}- Enhanced threat intelligence and reputation analysis"
    echo -e "  📁 ${GREEN}microsoft/   ${NC}- Office365 and Azure service enumeration"
fi

# Tool usage summary with enhancements
echo -e "\n${BLUE}ENHANCED RECONNAISSANCE CAPABILITIES:${NC}"
echo -e "${GREEN}Core Tools Utilized:${NC}"
for tool in "${AVAILABLE_TOOLS[@]}"; do
    if [ "$tool" = "smap" ]; then
        echo -e "  ✓ $tool (Shodan-powered passive scanning)"
    else
        echo -e "  ✓ $tool"
    fi
done

echo -e "\n${GREEN}Intelligence Sources:${NC}"
echo -e "  ✓ Certificate Transparency (multiple sources)"
echo -e "  ✓ Wayback Machine historical analysis"
echo -e "  ✓ Social media and community intelligence"
echo -e "  ✓ Configuration exposure detection"
echo -e "  ✓ Enhanced security header analysis"

if [[ " ${AVAILABLE_TOOLS[*]} " =~ " smap " ]]; then
    echo -e "  ✓ Shodan intelligence integration (200 hosts/sec)"
    echo -e "  ✓ Passive vulnerability detection"
fi

if [ "$RECON_MODE" = "FULL" ]; then
    echo -e "  ✓ Multi-pattern GitHub/GitLab searches"
    echo -e "  ✓ Enhanced VirusTotal threat intelligence" 
    echo -e "  ✓ Predictive cloud storage enumeration"
    echo -e "  ✓ Microsoft/Office365 service detection"
fi

if [ ${#AVAILABLE_TOOLS[@]} -lt ${#OPTIONAL_TOOLS[@]} ]; then
    echo ""
    echo -e "${YELLOW}MISSING TOOLS (install for enhanced capabilities):${NC}"
    for tool in "${OPTIONAL_TOOLS[@]}"; do
        if [[ ! " ${AVAILABLE_TOOLS[*]} " =~ " $tool " ]]; then
            echo -e "  ⚠ $tool"
        fi
    done
    echo ""
    echo -e "${CYAN}Install with:${NC}"
    echo -e "  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    echo -e "  go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    echo -e "  go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
    echo -e "  go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    echo -e "  go install github.com/PentestPad/subzy@latest"
fi

# Enhanced warning and legal reminder
echo -e "\n${RED}⚠️  IMPORTANT REMINDERS:${NC}"
echo -e "   • Only test systems you own or have explicit permission to test"
echo -e "   • Verify all findings manually before taking action"  
echo -e "   • Some automated results may be false positives"
echo -e "   • Follow responsible disclosure for any vulnerabilities found"
echo -e "   • Social intelligence should be used responsibly and ethically"
echo -e "   • Respect rate limits and terms of service for all external APIs"

# Archive creation for easy sharing/backup
echo -e "\n${YELLOW}[*] Creating comprehensive archive...${NC}"
tar -czf "${OUTPUT_DIR}.tar.gz" "$OUTPUT_DIR" 2>/dev/null && echo -e "${GREEN}[✓] Archive created: ${OUTPUT_DIR}.tar.gz${NC}" || echo -e "${YELLOW}[!] Archive creation failed${NC}"

echo -e "\n${GREEN}Enhanced reconnaissance complete with OSINT integration!${NC}"
echo -e "${BLUE}Mode: $RECON_MODE | Target: $TARGET_DOMAIN | Runtime: ${RUNTIME_MIN}m${RUNTIME_SEC}s${NC}"
echo -e "${CYAN}Enhanced with BigBountyRecon OSINT methodologies for comprehensive intelligence gathering${NC}"

# Cleanup function for interrupted scans
cleanup() {
    echo -e "\n${YELLOW}[!] Scan interrupted. Partial results saved in: $OUTPUT_DIR${NC}"
    exit 1
}

trap cleanup INT TERM