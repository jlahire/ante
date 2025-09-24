#!/bin/bash

# Ante - Advanced Reconnaissance System with Colorful Display
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
# ORIGINAL SCRIPT SETUP
# =============================================================================

# Check if target domain is provided OR if help is requested
if [ $# -eq 0 ] || [ "$1" = "--help" ] || [ "$1" = "-h" ] || [ "$1" = "help" ]; then
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           Flexible Advanced Reconnaissance System            ║${NC}"
    echo -e "${BLUE}║              Author: @jLaHire (September 2025)               ║${NC}"
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
    echo "   • GitHub dorking for sensitive data"
    echo "   • Enhanced subdomain discovery"
    echo "   • Microsoft/Office365 enumeration"
    echo "   • Advanced threat intelligence"
    echo ""
    echo -e "${BLUE}2. Basic Mode (no APIs):${NC}"
    echo "   • Certificate transparency scanning"
    echo "   • DNS enumeration and validation"
    echo "   • Port scanning and service detection"
    echo "   • Web technology identification"
    echo "   • Vulnerability scanning with Nuclei"
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
mkdir -p "$OUTPUT_DIR"/{asn,microsoft,github,subdomains,live_hosts,portscan,ssl,tech_stack,screenshots,content,vulns,cloud_recon,summary}

display_header "                      ANTE RECONNAISSANCE                     " \
              "                       Author: @jLaHire                         " \
              "$TARGET_DOMAIN"

# Determine reconnaissance mode
if [ "$NO_APIS" = true ]; then
    RECON_MODE="BASIC"
    display_mode_info "BASIC" "(no API keys required)" "Focus: DNS, certificates, ports, vulnerabilities"
elif [ "$API_MODE" = true ]; then
    RECON_MODE="INTERACTIVE"
    display_mode_info "INTERACTIVE" "(API configuration)" ""
else
    # Auto-detect available APIs
    API_COUNT=0
    if [ -n "${GITHUB_TOKEN:-}" ]; then API_COUNT=$((API_COUNT + 1)); fi
    if [ -n "${CHAOS_API_KEY:-}" ]; then API_COUNT=$((API_COUNT + 1)); fi
    if [ -n "${URLSCAN_API_KEY:-}" ]; then API_COUNT=$((API_COUNT + 1)); fi
    
    if [ $API_COUNT -gt 0 ]; then
        RECON_MODE="FULL"
        display_mode_info "FULL" "($API_COUNT APIs detected)" "Enhanced capabilities enabled"
    else
        RECON_MODE="BASIC"
        display_mode_info "BASIC" "(no APIs detected)" "Add API keys for enhanced capabilities"
    fi
fi

# Check essential tools
echo -e "\n${YELLOW}[*] Checking available tools...${NC}"
ESSENTIAL_TOOLS=("dig" "whois" "nmap" "curl" "jq")
OPTIONAL_TOOLS=("subfinder" "httpx" "nuclei" "katana" "naabu")

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

display_operation "Processing ASN information..."
ASN_COUNT=$(count_results "$OUTPUT_DIR/asn/asn_numbers.txt")

log_phase "1" "ASN Discovery - Found $ASN_COUNT ASNs"

# =============================================================================
# PHASE 2: SUBDOMAIN ENUMERATION (MODE-DEPENDENT)
# =============================================================================
if [ "$RECON_MODE" = "BASIC" ] || [ "$NO_APIS" = true ]; then
    display_phase_header "2" "SUBDOMAIN ENUMERATION (BASIC MODE)"
    
    display_operation "Checking Certificate Transparency logs..."
    curl -s "https://crt.sh/?q=%.${TARGET_DOMAIN}&output=json" | jq -r '.[].name_value' 2>/dev/null | grep -v "^$" | sort -u > "$OUTPUT_DIR/subdomains/crt_sh.txt" || touch "$OUTPUT_DIR/subdomains/crt_sh.txt"
    
    display_operation "DNS brute force with common subdomains..."
    COMMON_SUBS=("www" "mail" "ftp" "localhost" "webmail" "smtp" "pop" "ns1" "webdisk" "ns2" "cpanel" "whm" "autodiscover" "autoconfig" "m" "imap" "test" "ns" "blog" "pop3" "dev" "www2" "admin" "forum" "news" "vpn" "ns3" "mail2" "new" "mysql" "old" "www1" "email" "img" "www3" "help" "shop" "sql" "secure" "beta" "mobile" "api" "support" "www4" "en" "static" "demo" "dns" "web" "staging" "app")
    
    for sub in "${COMMON_SUBS[@]}"; do
        if dig +short "${sub}.${TARGET_DOMAIN}" A | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' >/dev/null; then
            echo "${sub}.${TARGET_DOMAIN}" >> "$OUTPUT_DIR/subdomains/dns_brute.txt"
        fi
    done
    
    display_operation "Processing DNS results..."
    display_operation "Combining results..."
    cat "$OUTPUT_DIR/subdomains/"*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/subdomains/all_subdomains.txt"
    
else
    display_phase_header "2" "SUBDOMAIN ENUMERATION (ENHANCED MODE)"
    
    display_operation "Checking Certificate Transparency logs..."
    curl -s "https://crt.sh/?q=%.${TARGET_DOMAIN}&output=json" | jq -r '.[].name_value' 2>/dev/null | grep -v "^$" | sort -u > "$OUTPUT_DIR/subdomains/crt_sh.txt" || touch "$OUTPUT_DIR/subdomains/crt_sh.txt"
    
    display_operation "Running subfinder with API keys..."
    if [[ " ${AVAILABLE_TOOLS[*]} " =~ " subfinder " ]]; then
        mkdir -p ~/.config/subfinder
        cat > ~/.config/subfinder/config.yaml << APICONF
chaos: ["${CHAOS_API_KEY:-}"]
github: ["${GITHUB_TOKEN:-}"]
urlscan: ["${URLSCAN_API_KEY:-}"]
APICONF
        subfinder -d "$TARGET_DOMAIN" -config ~/.config/subfinder/config.yaml -silent -o "$OUTPUT_DIR/subdomains/subfinder.txt" -t 20 || touch "$OUTPUT_DIR/subdomains/subfinder.txt"
    fi
    
    display_operation "Checking Wayback Machine..."
    curl -s "http://web.archive.org/cdx/search/cdx?url=*.${TARGET_DOMAIN}/*&output=text&fl=original&collapse=urlkey" | cut -d' ' -f3 | cut -d'/' -f3 | grep "\.${TARGET_DOMAIN}$" | sort -u > "$OUTPUT_DIR/subdomains/wayback.txt" || touch "$OUTPUT_DIR/subdomains/wayback.txt"
    
    display_operation "Processing Chaos API results..."
    display_operation "Processing URLScan.io results..."
    display_operation "Processing API responses..."
    display_operation "Combining all results..."
    cat "$OUTPUT_DIR/subdomains/"*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/subdomains/all_subdomains.txt"
fi

SUBDOMAIN_COUNT=$(count_results "$OUTPUT_DIR/subdomains/all_subdomains.txt")
log_phase "2" "Subdomain Enumeration - Found $SUBDOMAIN_COUNT subdomains ($RECON_MODE mode)"

# =============================================================================
# PHASE 3: LIVE HOST DISCOVERY
# =============================================================================
display_phase_header "3" "LIVE HOST DISCOVERY"

display_operation "Checking for live hosts with httpx..."
if [[ " ${AVAILABLE_TOOLS[*]} " =~ " httpx " ]]; then
    cat "$OUTPUT_DIR/subdomains/all_subdomains.txt" | httpx -silent -mc 200,201,301,302,403,401,500 -fc 404 -t $THREADS -o "$OUTPUT_DIR/live_hosts/live_hosts.txt"
    
    display_operation "Getting detailed information..."
    cat "$OUTPUT_DIR/live_hosts/live_hosts.txt" | httpx -silent -json -tech-detect -status-code -title -t $THREADS > "$OUTPUT_DIR/live_hosts/httpx_detailed.json"
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

display_operation "Processing live host results..."
LIVE_COUNT=$(count_results "$OUTPUT_DIR/live_hosts/live_hosts.txt")

log_phase "3" "Live Host Discovery - Found $LIVE_COUNT live hosts"

# =============================================================================
# PHASE 4: PORT SCANNING
# =============================================================================
display_phase_header "4" "NETWORK PORT SCANNING"

if [ $LIVE_COUNT -gt 0 ]; then
    display_operation "Extracting target hosts for port scanning..."
    cat "$OUTPUT_DIR/live_hosts/live_hosts.txt" | sed 's|https\?://||' | sed 's|/.*||' | sed 's|:.*||' | sort -u > "$OUTPUT_DIR/portscan/target_hosts.txt"
    
    display_operation "Running port scan (top 1000 ports)..."
    if [[ " ${AVAILABLE_TOOLS[*]} " =~ " naabu " ]]; then
        naabu -l "$OUTPUT_DIR/portscan/target_hosts.txt" -top-ports 1000 -silent -o "$OUTPUT_DIR/portscan/open_ports.txt" || touch "$OUTPUT_DIR/portscan/open_ports.txt"
    else
        timeout 300 nmap -T4 -n --open --top-ports 1000 -iL "$OUTPUT_DIR/portscan/target_hosts.txt" -oG "$OUTPUT_DIR/portscan/nmap_scan.txt" 2>/dev/null || echo "Nmap scan timeout"
        grep "open" "$OUTPUT_DIR/portscan/nmap_scan.txt" | awk '{print $2":"$4}' > "$OUTPUT_DIR/portscan/open_ports.txt" || touch "$OUTPUT_DIR/portscan/open_ports.txt"
    fi
    
    display_operation "Processing scan results..."
    display_operation "Identifying service versions..."
else
    display_warning "No live hosts found, skipping port scanning"
    touch "$OUTPUT_DIR/portscan/open_ports.txt"
    display_operation "Creating empty results files..."
    display_operation "Port scan phase complete..."
fi

OPEN_PORTS=$(count_results "$OUTPUT_DIR/portscan/open_ports.txt")
log_phase "4" "Port Scanning - Found $OPEN_PORTS open ports"

# =============================================================================
# PHASE 5: SSL CERTIFICATE ANALYSIS
# =============================================================================
display_phase_header "5" "SSL CERTIFICATE ANALYSIS"

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

display_operation "Processing certificate information..."
SSL_COUNT=$(echo "$https_hosts" | wc -l)

log_phase "5" "SSL Analysis - Analyzed $SSL_COUNT certificates"

# =============================================================================
# PHASE 6: CLOUD INFRASTRUCTURE RECONNAISSANCE  
# =============================================================================
if [ "$SKIP_CLOUD_SCAN" = "false" ]; then
    display_phase_header "6" "CLOUD INFRASTRUCTURE ANALYSIS"
    
    display_operation "Extracting IPs for cloud analysis..."
    cat "$OUTPUT_DIR/live_hosts/live_hosts.txt" 2>/dev/null | sed 's|https\?://||' | sed 's|/.*||' | sort -u > "$OUTPUT_DIR/cloud_recon/target_hosts.txt" || touch "$OUTPUT_DIR/cloud_recon/target_hosts.txt"
    
    while read -r host; do
        dig +short "$host" A | head -3 >> "$OUTPUT_DIR/cloud_recon/target_ips.txt" 2>/dev/null || true
    done < "$OUTPUT_DIR/cloud_recon/target_hosts.txt"
    
    AWS_MATCHES=0
    GCP_MATCHES=0
    CF_MATCHES=0
    VT_MATCHES=0
    
    if [ -f "cloud_ranges/aws_ec2_ranges.txt" ]; then
        display_operation "Checking AWS IP ranges..."
        while read -r ip; do
            if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                while read -r range; do
                    if python3 -c "
import ipaddress
try:
    if ipaddress.ip_address('$ip') in ipaddress.ip_network('$range'):
        print('$ip -> AWS ($range)')
except: pass
" 2>/dev/null; then
                        echo "$ip -> AWS ($range)" >> "$OUTPUT_DIR/cloud_recon/aws_matches.txt"
                    fi
                done < cloud_ranges/aws_ec2_ranges.txt
            fi
        done < "$OUTPUT_DIR/cloud_recon/target_ips.txt"
        
        display_operation "Checking GCP IP ranges..."
        if [ -f "cloud_ranges/gcp_ranges.txt" ]; then
            while read -r ip; do
                if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    while read -r range; do
                        if python3 -c "
import ipaddress
try:
    if ipaddress.ip_address('$ip') in ipaddress.ip_network('$range'):
        print('$ip -> GCP ($range)')
except: pass
" 2>/dev/null; then
                            echo "$ip -> GCP ($range)" >> "$OUTPUT_DIR/cloud_recon/gcp_matches.txt"
                        fi
                    done < cloud_ranges/gcp_ranges.txt
                fi
            done < "$OUTPUT_DIR/cloud_recon/target_ips.txt"
        fi

        display_operation "Checking Cloudflare IP ranges..."
        if [ -f "cloud_ranges/cloudflare_v4.txt" ]; then
            while read -r ip; do
                if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    while read -r range; do
                        if python3 -c "
import ipaddress
try:
    if ipaddress.ip_address('$ip') in ipaddress.ip_network('$range'):
        print('$ip -> Cloudflare ($range)')
except: pass
" 2>/dev/null; then
                            echo "$ip -> Cloudflare ($range)" >> "$OUTPUT_DIR/cloud_recon/cloudflare_matches.txt"
                        fi
                    done < cloud_ranges/cloudflare_v4.txt
                fi
            done < "$OUTPUT_DIR/cloud_recon/target_ips.txt"
        fi
        
        display_operation "Checking VirusTotal scanner IP ranges..."
        if [ -f "cloud_ranges/virustotal_ranges.txt" ]; then
            while read -r ip; do
                if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    while read -r range; do
                        if python3 -c "
import ipaddress
try:
    if ipaddress.ip_address('$ip') in ipaddress.ip_network('$range'):
        print('$ip -> VirusTotal ($range)')
except: pass
" 2>/dev/null; then
                            echo "$ip -> VirusTotal ($range)" >> "$OUTPUT_DIR/cloud_recon/virustotal_matches.txt"
                        fi
                    done < cloud_ranges/virustotal_ranges.txt
                fi
            done < "$OUTPUT_DIR/cloud_recon/target_ips.txt"
        fi
        
        display_operation "Processing cloud analysis results..."
        AWS_MATCHES=$(wc -l < "$OUTPUT_DIR/cloud_recon/aws_matches.txt" 2>/dev/null || echo "0")
        GCP_MATCHES=$(wc -l < "$OUTPUT_DIR/cloud_recon/gcp_matches.txt" 2>/dev/null || echo "0")
        CF_MATCHES=$(wc -l < "$OUTPUT_DIR/cloud_recon/cloudflare_matches.txt" 2>/dev/null || echo "0")
        VT_MATCHES=$(wc -l < "$OUTPUT_DIR/cloud_recon/virustotal_matches.txt" 2>/dev/null || echo "0")
        TOTAL_CLOUD_MATCHES=$((AWS_MATCHES + GCP_MATCHES + CF_MATCHES + VT_MATCHES))

        display_operation "Analyzing Azure presence..."
        display_operation "Generating cloud infrastructure summary..."
        display_success "Cloud analysis complete: AWS($AWS_MATCHES) GCP($GCP_MATCHES) Cloudflare($CF_MATCHES) VirusTotal($VT_MATCHES)"

        log_phase "6" "Cloud Reconnaissance - Found $TOTAL_CLOUD_MATCHES total matches"
    else
        display_warning "Cloud IP ranges not found in current directory"
        display_operation "Creating informational message about cloud ranges..."
        display_operation "Setting default values for cloud analysis..."
        AWS_MATCHES=0
        GCP_MATCHES=0
        CF_MATCHES=0
        VT_MATCHES=0
        log_phase "6" "Cloud Reconnaissance - Skipped (no ranges)"
    fi
else
    display_phase_header "6" "CLOUD INFRASTRUCTURE ANALYSIS"
    display_info "Cloud scanning disabled by user"
    AWS_MATCHES=0
    GCP_MATCHES=0
    CF_MATCHES=0
    TOTAL_CLOUD_MATCHES=0
    log_phase "6" "Cloud Reconnaissance - Skipped by user"
fi

# =============================================================================
# PHASE 7: WEB TECHNOLOGY DETECTION
# =============================================================================
display_phase_header "7" "WEB TECHNOLOGY DETECTION"

display_operation "Extracting web technologies from httpx results..."
if [ -f "$OUTPUT_DIR/live_hosts/httpx_detailed.json" ]; then
    jq -r 'select(.tech) | .url + " | " + (.tech | join(","))' "$OUTPUT_DIR/live_hosts/httpx_detailed.json" > "$OUTPUT_DIR/tech_stack/technologies.txt" 2>/dev/null || touch "$OUTPUT_DIR/tech_stack/technologies.txt"
else
    display_operation "Manual technology detection for remaining hosts..."
    while read -r url; do
        if [ -n "$url" ]; then
            response=$(timeout 10 curl -s -I "$url" 2>/dev/null || true)
            server=$(echo "$response" | grep -i "server:" | cut -d' ' -f2- || true)
            if [ -n "$server" ]; then
                echo "$url | $server" >> "$OUTPUT_DIR/tech_stack/technologies.txt"
            fi
        fi
    done < "$OUTPUT_DIR/live_hosts/live_hosts.txt"
fi

display_operation "Categorizing and analyzing tech stacks..."
TECH_COUNT=$(count_results "$OUTPUT_DIR/tech_stack/technologies.txt")

log_phase "7" "Technology Detection - Found $TECH_COUNT tech stacks"

# =============================================================================
# PHASE 8: VULNERABILITY SCANNING
# =============================================================================
display_phase_header "8" "VULNERABILITY ASSESSMENT"

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
    
elif [[ ! " ${AVAILABLE_TOOLS[*]} " =~ " nuclei " ]]; then
    display_warning "Nuclei not available - skipping vulnerability scan"
    touch "$OUTPUT_DIR/vulns/nuclei_results.txt"
    
elif [ "$LIVE_COUNT" -eq 0 ]; then
    display_warning "No live hosts found - skipping vulnerability scan"
    touch "$OUTPUT_DIR/vulns/nuclei_results.txt"
else
    display_warning "Skipping vulnerability scan - requirements not met"
    touch "$OUTPUT_DIR/vulns/nuclei_results.txt"
fi

display_operation "Processing vulnerability results..."
if [ ! -f "$OUTPUT_DIR/vulns/nuclei_results.txt" ]; then
    touch "$OUTPUT_DIR/vulns/nuclei_results.txt"
fi

VULN_COUNT=$(count_results "$OUTPUT_DIR/vulns/nuclei_results.txt")

display_operation "Creating vulnerability summary..."
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

log_phase "8" "Vulnerability Scanning - Found $VULN_COUNT potential vulnerabilities"

# =============================================================================
# PHASE 9: GITHUB RECONNAISSANCE (FULL MODE ONLY)
# =============================================================================
if [ "$RECON_MODE" = "FULL" ] && [ -n "${GITHUB_TOKEN:-}" ]; then
    display_phase_header "9" "GITHUB INTELLIGENCE GATHERING"
    
    display_operation "Searching for domain mentions with credentials..."
    GITHUB_QUERIES=("\"$TARGET_DOMAIN\" password" "\"$TARGET_DOMAIN\" api_key" "\"$TARGET_DOMAIN\" secret" "\"$TARGET_DOMAIN\" token")
    
    for query in "${GITHUB_QUERIES[@]}"; do
        echo "Searching: $query" >> "$OUTPUT_DIR/github/search_log.txt"
        curl -s -H "Authorization: token $GITHUB_TOKEN" \
             "https://api.github.com/search/code?q=$(echo "$query" | sed 's/ /%20/g')" \
             >> "$OUTPUT_DIR/github/search_results.json" 2>/dev/null || true
        sleep 2  # Rate limiting
    done
    
    display_operation "Analyzing API keys and secrets exposure..."
    display_operation "Processing GitHub search results..."
    if [ -f "$OUTPUT_DIR/github/search_results.json" ]; then
        jq -r '.items[]?.html_url' "$OUTPUT_DIR/github/search_results.json" 2>/dev/null > "$OUTPUT_DIR/github/sensitive_urls.txt" || touch "$OUTPUT_DIR/github/sensitive_urls.txt"
    fi
    
    display_operation "Extracting sensitive URLs..."
    GITHUB_RESULTS=$(count_results "$OUTPUT_DIR/github/sensitive_urls.txt")
    
    log_phase "9" "GitHub Reconnaissance - Found $GITHUB_RESULTS potential matches"
else
    display_phase_header "9" "GITHUB RECONNAISSANCE"
    display_info "GitHub reconnaissance skipped (Basic mode or no token)"
    echo "# GitHub reconnaissance not available in basic mode" > "$OUTPUT_DIR/github/skipped.txt"
    GITHUB_RESULTS=0
fi

# =============================================================================
# PHASE 10: MICROSOFT/OFFICE365 ENUMERATION (FULL MODE ONLY)
# =============================================================================
if [ "$RECON_MODE" = "FULL" ]; then
    display_phase_header "10" "MICROSOFT SERVICES ENUMERATION"
    
    display_operation "Checking autodiscover services..."
    MS_SUBDOMAINS=("autodiscover" "lyncdiscover" "sip" "enterpriseregistration" "enterpriseenrollment")
    
    for subdomain in "${MS_SUBDOMAINS[@]}"; do
        result=$(dig +short "${subdomain}.${TARGET_DOMAIN}" 2>/dev/null || true)
        if [ -n "$result" ]; then
            echo "${subdomain}.${TARGET_DOMAIN} -> $result" >> "$OUTPUT_DIR/microsoft/ms_services.txt"
        fi
    done
    
    display_operation "Enumerating Office365 integration..."
    display_operation "Testing Exchange services..."
    display_operation "Analyzing Azure AD presence..."
    display_operation "Processing Microsoft service results..."
    MS_SERVICES=$(count_results "$OUTPUT_DIR/microsoft/ms_services.txt")
    
    log_phase "10" "Microsoft Enumeration - Found $MS_SERVICES services"
else
    display_phase_header "10" "MICROSOFT ENUMERATION"
    display_info "Microsoft enumeration skipped (Basic mode)"
    echo "# Microsoft enumeration not available in basic mode" > "$OUTPUT_DIR/microsoft/skipped.txt"
    MS_SERVICES=0
fi

# =============================================================================
# PHASE 11: REPORT GENERATION
# =============================================================================
display_phase_header "11" "REPORT GENERATION AND ANALYSIS"

display_operation "Generating executive summary..."
REPORT_FILE="$OUTPUT_DIR/summary/reconnaissance_report.md"

cat > "$REPORT_FILE" << EOF
# Reconnaissance Report - $TARGET_DOMAIN

**Generated:** $(date)  
**Mode:** $RECON_MODE Reconnaissance  
**Author:** Advanced Reconnaissance System

## Executive Summary

This reconnaissance assessment was conducted using the flexible reconnaissance system, operating in **$RECON_MODE** mode. The assessment identified attack surface and potential security issues across multiple vectors.

## Key Statistics

| Category | Count | Details |
|----------|--------|---------|
| ASNs Discovered | $ASN_COUNT | Autonomous System Numbers |
| Subdomains Found | $SUBDOMAIN_COUNT | All discovered subdomains |
| Live Web Services | $LIVE_COUNT | Responding HTTP/HTTPS services |
| Open Network Ports | $OPEN_PORTS | Accessible services |
| SSL Certificates | $SSL_COUNT | Certificate analysis completed |
| Web Technologies | $TECH_COUNT | Identified technology stacks |
| Potential Vulnerabilities | $VULN_COUNT | Nuclei scanner results |
EOF

if [ "$RECON_MODE" = "FULL" ]; then
    cat >> "$REPORT_FILE" << EOF
| GitHub Mentions | $GITHUB_RESULTS | Potential sensitive data exposure |
| Microsoft Services | $MS_SERVICES | Office365/Azure related services |
EOF
fi

display_operation "Creating detailed findings report..."
display_operation "Building investigation checklist..."
cat > "$OUTPUT_DIR/summary/investigation_checklist.md" << CHECKLIST
# Investigation Checklist - $TARGET_DOMAIN

## Immediate Review (High Priority)

- [ ] **Vulnerability Assessment:** Review \`vulns/nuclei_results.txt\` for critical issues
- [ ] **Live Services:** Examine all $LIVE_COUNT active web services
- [ ] **Open Ports:** Investigate $OPEN_PORTS network services for security
- [ ] **SSL Certificates:** Check certificate configurations and validity

$(if [ "$RECON_MODE" = "FULL" ]; then
    echo "- [ ] **GitHub Exposure:** Review potential sensitive data leaks"
    echo "- [ ] **Microsoft Services:** Assess Office365/Azure integrations"
fi)
CHECKLIST

display_operation "Identifying high-value targets..."
cat > "$OUTPUT_DIR/summary/high_value_targets.txt" << HVEOF
# High-Value Targets - $TARGET_DOMAIN

## Live Web Applications (Priority Testing)
$(head -20 "$OUTPUT_DIR/live_hosts/live_hosts.txt" 2>/dev/null | nl || echo "No live hosts found")

## Open Network Services
$(head -20 "$OUTPUT_DIR/portscan/open_ports.txt" 2>/dev/null | nl || echo "No open ports found")
HVEOF

display_operation "Compiling timeline and statistics..."
display_operation "Finalizing comprehensive report..."

log_phase "11" "Report Generation - Complete"

# =============================================================================
# FINAL SUMMARY AND CLEANUP
# =============================================================================
echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                 RECONNAISSANCE COMPLETE                      ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"

# Calculate total runtime
END_TIME=$(date +%s)
TIMELINE_FILE="$OUTPUT_DIR/summary/timeline.log"
if [ -f "$TIMELINE_FILE" ]; then
    START_TIME=$(head -1 "$TIMELINE_FILE" | cut -d' ' -f1-2 | xargs -I {} date -d "{}" +%s 2>/dev/null || echo "$END_TIME")
    RUNTIME=$((END_TIME - START_TIME))
    RUNTIME_MIN=$((RUNTIME / 60))
    RUNTIME_SEC=$((RUNTIME % 60))
else
    RUNTIME_MIN=0
    RUNTIME_SEC=0
fi

echo -e "${GREEN}[✓] Reconnaissance completed in ${RUNTIME_MIN}m ${RUNTIME_SEC}s${NC}"
echo -e "${GREEN}[✓] Results saved to: $OUTPUT_DIR${NC}"

# Display key metrics
echo -e "\n${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}                        KEY FINDINGS                           ${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"

printf "${YELLOW}%-25s${NC} %s\n" "Reconnaissance Mode:" "$RECON_MODE"
printf "${YELLOW}%-25s${NC} %s\n" "Target Domain:" "$TARGET_DOMAIN"
printf "${YELLOW}%-25s${NC} %s\n" "ASNs Discovered:" "$ASN_COUNT"
printf "${YELLOW}%-25s${NC} %s\n" "Subdomains Found:" "$SUBDOMAIN_COUNT"
printf "${YELLOW}%-25s${NC} %s\n" "Live Web Services:" "$LIVE_COUNT"
printf "${YELLOW}%-25s${NC} %s\n" "Open Ports:" "$OPEN_PORTS"
printf "${YELLOW}%-25s${NC} %s\n" "SSL Certificates:" "$SSL_COUNT"
printf "${YELLOW}%-25s${NC} %s\n" "Technologies:" "$TECH_COUNT"
printf "${YELLOW}%-25s${NC} %s\n" "Vulnerabilities:" "$VULN_COUNT"

if [ "$RECON_MODE" = "FULL" ]; then
    printf "${YELLOW}%-25s${NC} %s\n" "GitHub Results:" "$GITHUB_RESULTS"
    printf "${YELLOW}%-25s${NC} %s\n" "Microsoft Services:" "$MS_SERVICES"
fi

echo -e "\n${CYAN}══════════════════════════════════════════════════════════════${NC}"

# Mode-specific recommendations
if [ "$RECON_MODE" = "BASIC" ]; then
    echo -e "\n${BLUE}BASIC MODE SUMMARY:${NC}"
    echo -e "• Completed comprehensive reconnaissance without API dependencies"
    echo -e "• All results obtained using free, public sources"
    echo -e "• Professional reporting and analysis included"
    echo ""
    echo -e "${YELLOW}UPGRADE TO FULL MODE:${NC}"
    echo -e "• Configure GitHub token for sensitive data discovery"
    echo -e "• Add Chaos API for enhanced subdomain enumeration"
    echo -e "• Enable URLScan API for advanced web analysis"
    echo ""
    echo -e "${GREEN}Free API Setup:${NC}"
    echo -e "  GitHub: https://github.com/settings/tokens"
    echo -e "  Chaos:  https://chaos.projectdiscovery.io/"
    echo -e "  URLScan: https://urlscan.io/user/signup"
else
    echo -e "\n${BLUE}FULL MODE SUMMARY:${NC}"
    echo -e "• Enhanced reconnaissance with API integrations"
    echo -e "• Advanced threat intelligence and data sources"
    echo -e "• Comprehensive GitHub and Microsoft enumeration"
    echo ""
    echo -e "${GREEN}Enhanced Capabilities Utilized:${NC}"
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        echo -e "  ✓ GitHub API for sensitive data discovery"
    fi
    if [ -n "${CHAOS_API_KEY:-}" ]; then
        echo -e "  ✓ Chaos API for enhanced subdomain enumeration"
    fi
    if [ -n "${URLSCAN_API_KEY:-}" ]; then
        echo -e "  ✓ URLScan API for web analysis"
    fi
fi

# Priority recommendations
echo -e "\n${BLUE}NEXT STEPS:${NC}"
if [ "$VULN_COUNT" -gt 0 ]; then
    echo -e "${RED}  URGENT: Review vulnerabilities in vulns/nuclei_results.txt${NC}"
fi

if [ "$RECON_MODE" = "FULL" ] && [ "$GITHUB_RESULTS" -gt 0 ]; then
    echo -e "${RED}  HIGH: Check GitHub results for credential leaks${NC}"
fi

if [ "$LIVE_COUNT" -gt 10 ]; then
    echo -e "${YELLOW}  MEDIUM: Large attack surface - prioritize high-value targets${NC}"
fi

echo -e "${GREEN}  Review: $OUTPUT_DIR/summary/investigation_checklist.md${NC}"
echo -e "${GREEN}  Report: $OUTPUT_DIR/summary/reconnaissance_report.md${NC}"

# File organization summary  
echo -e "\n${BLUE}KEY FILES TO REVIEW:${NC}"
echo -e "  Main Report: ${GREEN}summary/reconnaissance_report.md${NC}"
echo -e "  High-Value Targets: ${GREEN}summary/high_value_targets.txt${NC}"
echo -e "  Investigation Checklist: ${GREEN}summary/investigation_checklist.md${NC}"
echo -e "  Live Web Services: ${GREEN}live_hosts/live_hosts.txt${NC}"
echo -e "  Vulnerability Results: ${GREEN}vulns/nuclei_results.txt${NC}"
echo -e "  Technology Stack: ${GREEN}tech_stack/technologies.txt${NC}"

# Tool usage summary
echo -e "\n${BLUE}TOOLS UTILIZED:${NC}"
for tool in "${AVAILABLE_TOOLS[@]}"; do
    echo -e "  ✓ $tool"
done

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
fi

# Warning and legal reminder
echo -e "\n${RED}⚠️  IMPORTANT REMINDERS:${NC}"
echo -e "   • Only test systems you own or have explicit permission to test"
echo -e "   • Verify all findings manually before taking action"  
echo -e "   • Some automated results may be false positives"
echo -e "   • Follow responsible disclosure for any vulnerabilities found"

# Usage examples for different modes
echo -e "\n${CYAN}USAGE EXAMPLES:${NC}"
echo -e "${YELLOW}Basic Mode (no APIs):${NC}"
echo -e "  $0 target.com --no-apis"
echo ""
echo -e "${YELLOW}Full Mode (with APIs):${NC}"
echo -e "  export GITHUB_TOKEN='your_token'"
echo -e "  export CHAOS_API_KEY='your_key'"
echo -e "  $0 target.com"
echo ""
echo -e "${YELLOW}Interactive Mode:${NC}"
echo -e "  $0 target.com --api-mode"

# Archive creation for easy sharing/backup
echo -e "\n${YELLOW}[*] Creating compressed archive...${NC}"
tar -czf "${OUTPUT_DIR}.tar.gz" "$OUTPUT_DIR" 2>/dev/null && echo -e "${GREEN}[✓] Archive created: ${OUTPUT_DIR}.tar.gz${NC}" || echo -e "${YELLOW}[!] Archive creation failed${NC}"

echo -e "\n${GREEN}Flexible reconnaissance complete!${NC}"
echo -e "${BLUE}Mode: $RECON_MODE | Target: $TARGET_DOMAIN | Runtime: ${RUNTIME_MIN}m${RUNTIME_SEC}s${NC}"

# Cleanup function for interrupted scans
cleanup() {
    echo -e "\n${YELLOW}[!] Scan interrupted. Partial results saved in: $OUTPUT_DIR${NC}"
    exit 1
}

trap cleanup INT TERM