#!/bin/bash

# Cloud Provider IP Range Updater for Ante Reconnaissance System
# Downloads and maintains current IP ranges for comprehensive cloud provider detection
# Author: @jLaHire - September 2025

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Determine script location and cloud ranges directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RANGES_DIR="$SCRIPT_DIR/cloud_ranges"

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         Comprehensive Cloud Provider Range Updater          ║${NC}"
echo -e "${BLUE}║         Covers major cloud providers and CDN networks        ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"

# Create ranges directory if it doesn't exist
if [ ! -d "$RANGES_DIR" ]; then
    echo -e "\n${YELLOW}[*] Creating cloud ranges directory...${NC}"
    mkdir -p "$RANGES_DIR"
fi

cd "$RANGES_DIR"

# Function to display download status
download_status() {
    local service="$1"
    local status="$2"
    local count="$3"
    
    if [ "$status" = "success" ]; then
        echo -e "${GREEN}[+] $service: Downloaded $count IP ranges${NC}"
    elif [ "$status" = "error" ]; then
        echo -e "${RED}[-] $service: Download failed, using fallback${NC}"
    elif [ "$status" = "parse_error" ]; then
        echo -e "${YELLOW}[!] $service: Downloaded but parsing failed, using fallback${NC}"
    fi
}

# =============================================================================
# MAJOR CLOUD PROVIDERS
# =============================================================================

echo -e "\n${CYAN}[1/11] Downloading AWS IP Ranges...${NC}"
if curl -s -f https://ip-ranges.amazonaws.com/ip-ranges.json -o aws-ip-ranges.json; then
    if command -v jq >/dev/null 2>&1; then
        if jq -r '.prefixes[] | select(.service=="EC2") | .ip_prefix' aws-ip-ranges.json > aws_ec2_ranges.txt 2>/dev/null; then
            AWS_COUNT=$(wc -l < aws_ec2_ranges.txt)
            download_status "AWS EC2" "success" "$AWS_COUNT"
        else
            echo -e "# AWS EC2 IP ranges (fallback)\n54.239.0.0/16\n52.0.0.0/8\n34.192.0.0/10" > aws_ec2_ranges.txt
            download_status "AWS EC2" "parse_error" "3"
        fi
    else
        echo -e "# AWS EC2 IP ranges (no jq)\n54.239.0.0/16\n52.0.0.0/8" > aws_ec2_ranges.txt
        download_status "AWS EC2" "parse_error" "2"
    fi
else
    echo -e "# AWS EC2 ranges unavailable\n52.0.0.0/8" > aws_ec2_ranges.txt
    download_status "AWS EC2" "error" "1"
fi

echo -e "\n${CYAN}[2/11] Downloading Google Cloud Platform IP Ranges...${NC}"
if curl -s -f https://www.gstatic.com/ipranges/cloud.json -o gcp-cloud.json; then
    if command -v jq >/dev/null 2>&1; then
        if jq -r '.prefixes[].ipv4Prefix | select(. != null)' gcp-cloud.json > gcp_ranges.txt 2>/dev/null; then
            GCP_COUNT=$(wc -l < gcp_ranges.txt)
            download_status "GCP" "success" "$GCP_COUNT"
        else
            echo -e "# GCP IP ranges (fallback)\n35.199.0.0/16\n34.0.0.0/8\n104.196.0.0/14" > gcp_ranges.txt
            download_status "GCP" "parse_error" "3"
        fi
    else
        echo -e "# GCP IP ranges (no jq)\n35.199.0.0/16\n34.0.0.0/8" > gcp_ranges.txt
        download_status "GCP" "parse_error" "2"
    fi
else
    echo -e "# GCP ranges unavailable\n34.0.0.0/8" > gcp_ranges.txt
    download_status "GCP" "error" "1"
fi

echo -e "\n${CYAN}[3/11] Downloading Microsoft Azure IP Ranges...${NC}"
# Azure ranges are complex, try multiple sources
if curl -s -f "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519" | grep -o 'https://[^"]*ServiceTags[^"]*\.json' | head -1 | xargs curl -s -f > azure-ranges.json 2>/dev/null; then
    if command -v jq >/dev/null 2>&1; then
        if jq -r '.values[] | select(.name == "AzureCloud") | .properties.addressPrefixes[] | select(test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+$"))' azure-ranges.json > azure_ranges.txt 2>/dev/null; then
            AZURE_COUNT=$(wc -l < azure_ranges.txt)
            download_status "Azure" "success" "$AZURE_COUNT"
        else
            echo -e "# Azure IP ranges (fallback)\n13.64.0.0/11\n20.0.0.0/8\n40.64.0.0/10\n52.0.0.0/8\n104.40.0.0/13" > azure_ranges.txt
            download_status "Azure" "parse_error" "5"
        fi
    else
        echo -e "# Azure IP ranges (no jq)\n13.64.0.0/11\n20.0.0.0/8\n40.64.0.0/10" > azure_ranges.txt
        download_status "Azure" "parse_error" "3"
    fi
else
    echo -e "# Azure IP ranges (download failed)\n13.64.0.0/11\n20.0.0.0/8\n40.64.0.0/10\n52.0.0.0/8" > azure_ranges.txt
    download_status "Azure" "error" "4"
fi

echo -e "\n${CYAN}[4/11] Downloading Oracle Cloud Infrastructure IP Ranges...${NC}"
if curl -s -f https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json -o oracle-ranges.json; then
    if command -v jq >/dev/null 2>&1; then
        if jq -r '.regions[].cidrs[].cidr' oracle-ranges.json > oracle_ranges.txt 2>/dev/null && [ -s oracle_ranges.txt ]; then
            ORACLE_COUNT=$(wc -l < oracle_ranges.txt)
            download_status "Oracle Cloud" "success" "$ORACLE_COUNT"
        else
            echo -e "# Oracle Cloud IP ranges (fallback)\n129.213.0.0/16\n138.1.0.0/16\n140.91.0.0/16\n147.154.0.0/16" > oracle_ranges.txt
            download_status "Oracle Cloud" "parse_error" "4"
        fi
    else
        echo -e "# Oracle Cloud IP ranges (no jq)\n129.213.0.0/16\n138.1.0.0/16" > oracle_ranges.txt
        download_status "Oracle Cloud" "parse_error" "2"
    fi
else
    echo -e "# Oracle Cloud ranges unavailable\n129.213.0.0/16\n138.1.0.0/16" > oracle_ranges.txt
    download_status "Oracle Cloud" "error" "2"
fi

echo -e "\n${CYAN}[5/11] Downloading DigitalOcean IP Ranges...${NC}"
# DigitalOcean doesn't have a direct API, but we can get their ranges from various sources
if curl -s -f https://www.digitalocean.com/geo/google.csv -o digitalocean.csv && [ -s digitalocean.csv ]; then
    # Extract IP ranges from the CSV (simplified approach)
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' digitalocean.csv > digitalocean_ranges.txt 2>/dev/null || {
        echo -e "# DigitalOcean IP ranges (fallback)\n104.131.0.0/16\n159.89.0.0/16\n178.62.0.0/16\n46.101.0.0/16\n138.197.0.0/16\n167.99.0.0/16\n167.172.0.0/16" > digitalocean_ranges.txt
    }
    DO_COUNT=$(wc -l < digitalocean_ranges.txt)
    download_status "DigitalOcean" "success" "$DO_COUNT"
else
    echo -e "# DigitalOcean IP ranges (known ranges)\n104.131.0.0/16\n159.89.0.0/16\n178.62.0.0/16\n46.101.0.0/16\n138.197.0.0/16\n167.99.0.0/16\n167.172.0.0/16\n188.166.0.0/16\n188.226.0.0/16" > digitalocean_ranges.txt
    download_status "DigitalOcean" "error" "9"
fi

echo -e "\n${CYAN}[6/11] Creating Alibaba Cloud IP Ranges...${NC}"
# Alibaba Cloud doesn't provide public API, using known ranges
cat > alibaba_ranges.txt << ALIBABA
# Alibaba Cloud IP ranges (known ranges)
# Primary regions
47.88.0.0/13
47.96.0.0/11
8.208.0.0/13
8.217.0.0/16
47.240.0.0/12
47.74.0.0/15
47.76.0.0/14
47.80.0.0/12
149.129.0.0/16
116.62.0.0/15
120.24.0.0/13
121.40.0.0/13
121.43.0.0/16
39.96.0.0/13
39.104.0.0/13
ALIBABA
ALIBABA_COUNT=$(wc -l < alibaba_ranges.txt | grep -v '^#' | wc -l)
download_status "Alibaba Cloud" "success" "15"

# =============================================================================
# CDN AND EDGE NETWORKS
# =============================================================================

echo -e "\n${CYAN}[7/11] Downloading Cloudflare IP Ranges...${NC}"
if curl -s -f https://www.cloudflare.com/ips-v4 -o cloudflare_v4.txt; then
    CF_COUNT=$(wc -l < cloudflare_v4.txt)
    download_status "Cloudflare" "success" "$CF_COUNT"
else
    cat > cloudflare_v4.txt << CLOUDFLARE
# Cloudflare IP ranges (fallback)
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22
CLOUDFLARE
    download_status "Cloudflare" "error" "15"
fi

echo -e "\n${CYAN}[8/11] Downloading Fastly IP Ranges...${NC}"
if curl -s -f https://api.fastly.com/public-ip-list -o fastly-ranges.json; then
    if command -v jq >/dev/null 2>&1; then
        if jq -r '.addresses[]' fastly-ranges.json > fastly_ranges.txt 2>/dev/null; then
            FASTLY_COUNT=$(wc -l < fastly_ranges.txt)
            download_status "Fastly" "success" "$FASTLY_COUNT"
        else
            cat > fastly_ranges.txt << FASTLY
# Fastly IP ranges (fallback)
23.235.32.0/20
43.249.72.0/22
103.244.50.0/24
103.245.222.0/23
103.245.224.0/24
104.156.80.0/20
140.248.64.0/18
140.248.128.0/17
146.75.0.0/16
151.101.0.0/16
157.52.64.0/18
167.82.0.0/17
167.82.128.0/20
167.82.160.0/20
167.82.224.0/20
185.31.16.0/22
199.27.72.0/21
199.232.0.0/16
FASTLY
            download_status "Fastly" "parse_error" "18"
        fi
    else
        cat > fastly_ranges.txt << FASTLY
# Fastly IP ranges (no jq)
23.235.32.0/20
146.75.0.0/16
151.101.0.0/16
199.232.0.0/16
FASTLY
        download_status "Fastly" "parse_error" "4"
    fi
else
    cat > fastly_ranges.txt << FASTLY
# Fastly IP ranges (unavailable)
23.235.32.0/20
146.75.0.0/16
151.101.0.0/16
199.232.0.0/16
FASTLY
    download_status "Fastly" "error" "4"
fi

echo -e "\n${CYAN}[9/11] Creating Akamai IP Ranges...${NC}"
# Akamai doesn't provide comprehensive public ranges, using known ranges
cat > akamai_ranges.txt << AKAMAI
# Akamai IP ranges (known ranges)
# These are partial ranges - Akamai uses a vast distributed network
23.0.0.0/8
23.32.0.0/11
23.64.0.0/14
23.72.0.0/13
23.192.0.0/11
23.224.0.0/12
95.100.0.0/15
96.6.0.0/15
104.64.0.0/10
184.24.0.0/13
184.50.0.0/15
184.84.0.0/14
2.16.0.0/13
AKAMAI
download_status "Akamai" "success" "13"

echo -e "\n${CYAN}[10/11] Creating Additional Cloud Providers...${NC}"

# Vultr ranges (known)
cat > vultr_ranges.txt << VULTR
# Vultr IP ranges (known ranges)
45.32.0.0/16
45.63.0.0/16
45.76.0.0/16
63.209.32.0/19
64.176.0.0/12
66.42.0.0/16
104.207.128.0/18
108.61.0.0/16
144.202.0.0/16
149.28.0.0/16
155.138.128.0/17
192.248.160.0/19
199.247.0.0/16
207.148.0.0/18
VULTR
download_status "Vultr" "success" "14"

# Linode/Akamai ranges (known)
cat > linode_ranges.txt << LINODE
# Linode IP ranges (known ranges)
45.33.0.0/16
45.56.0.0/16
45.79.0.0/16
66.175.208.0/20
69.164.192.0/20
72.14.176.0/20
96.126.96.0/19
103.3.60.0/22
139.162.0.0/16
172.104.0.0/15
173.255.192.0/18
176.58.0.0/15
192.46.208.0/20
192.81.208.0/20
192.155.80.0/20
198.58.96.0/19
LINODE
download_status "Linode" "success" "16"

echo -e "\n${CYAN}[11/11] Creating summary and additional ranges...${NC}"

# IBM Cloud (basic ranges)
cat > ibm_ranges.txt << IBM
# IBM Cloud IP ranges (known ranges)
169.44.0.0/14
169.48.0.0/13
169.56.0.0/13
169.60.0.0/14
158.175.0.0/16
158.176.0.0/15
161.202.0.0/16
169.44.0.0/16
IBM
download_status "IBM Cloud" "success" "8"

# Create comprehensive summary
cat > range_summary.txt << SUMMARY
# Comprehensive Cloud Provider IP Range Summary
# Generated: $(date)
# Location: $RANGES_DIR

## Major Cloud Providers:
- aws_ec2_ranges.txt: $(wc -l < aws_ec2_ranges.txt) AWS EC2 ranges
- gcp_ranges.txt: $(wc -l < gcp_ranges.txt) Google Cloud Platform ranges  
- azure_ranges.txt: $(wc -l < azure_ranges.txt) Microsoft Azure ranges
- oracle_ranges.txt: $(wc -l < oracle_ranges.txt) Oracle Cloud ranges
- digitalocean_ranges.txt: $(wc -l < digitalocean_ranges.txt) DigitalOcean ranges
- alibaba_ranges.txt: $(grep -v '^#' alibaba_ranges.txt | wc -l) Alibaba Cloud ranges

## CDN and Edge Networks:
- cloudflare_v4.txt: $(wc -l < cloudflare_v4.txt) Cloudflare IPv4 ranges
- fastly_ranges.txt: $(grep -v '^#' fastly_ranges.txt | wc -l) Fastly CDN ranges
- akamai_ranges.txt: $(grep -v '^#' akamai_ranges.txt | wc -l) Akamai CDN ranges

## Additional Cloud Providers:
- vultr_ranges.txt: $(grep -v '^#' vultr_ranges.txt | wc -l) Vultr ranges
- linode_ranges.txt: $(grep -v '^#' linode_ranges.txt | wc -l) Linode ranges
- ibm_ranges.txt: $(grep -v '^#' ibm_ranges.txt | wc -l) IBM Cloud ranges

## Usage:
These files enable comprehensive cloud provider identification during 
reconnaissance. The Ante system uses these ranges to classify discovered
IP addresses and provide intelligence about infrastructure choices.

## Coverage:
- Major hyperscale cloud providers (AWS, Azure, GCP, Oracle)
- Regional cloud providers (Alibaba, DigitalOcean, Vultr, Linode)
- Content delivery networks (Cloudflare, Fastly, Akamai)
- Enterprise cloud services (IBM Cloud)

## Update Frequency:
Cloud providers update IP ranges regularly. Run this script:
- Weekly for active reconnaissance campaigns
- Monthly for general maintenance
- Before major assessments

## Dependencies:
- curl (required)
- jq (recommended for JSON parsing)
- Standard Unix tools (grep, sed, awk)
SUMMARY

# Calculate comprehensive statistics
TOTAL_RANGES=0
for file in *_ranges.txt *.txt; do
    if [ -f "$file" ] && [ "$file" != "range_summary.txt" ]; then
        count=$(grep -v '^#' "$file" 2>/dev/null | grep -v '^ -s -f > azure-ranges.json 2>/dev/null; then
    if command -v jq >/dev/null 2>&1; then
        if jq -r '.values[] | select(.name == "AzureCloud") | .properties.addressPrefixes[] | select(test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+$"))' azure-ranges.json > azure_ranges.txt 2>/dev/null; then
            AZURE_COUNT=$(wc -l < azure_ranges.txt)
            download_status "Azure" "success" "$AZURE_COUNT"
        else
            # Fallback for Azure
            echo "# Azure IP ranges (fallback)" > azure_ranges.txt
            echo "13.64.0.0/11" >> azure_ranges.txt
            echo "20.0.0.0/8" >> azure_ranges.txt
            echo "40.64.0.0/10" >> azure_ranges.txt
            echo "52.0.0.0/8" >> azure_ranges.txt
            echo "104.40.0.0/13" >> azure_ranges.txt
            download_status "Azure" "parse_error" "5"
        fi
    else
        echo "# Azure IP ranges (no jq available)" > azure_ranges.txt
        echo "13.64.0.0/11" >> azure_ranges.txt
        echo "20.0.0.0/8" >> azure_ranges.txt
        echo "40.64.0.0/10" >> azure_ranges.txt
        download_status "Azure" "parse_error" "3"
    fi
else
    # Basic Azure fallback ranges
    echo "# Azure IP ranges (download failed)" > azure_ranges.txt
    echo "13.64.0.0/11" >> azure_ranges.txt
    echo "20.0.0.0/8" >> azure_ranges.txt
    echo "40.64.0.0/10" >> azure_ranges.txt
    echo "52.0.0.0/8" >> azure_ranges.txt
    download_status "Azure" "error" "4"
fi

# Create summary report
echo -e "\n${YELLOW}[*] Creating range summary...${NC}"
cat > range_summary.txt << SUMMARY
# Cloud Provider IP Range Summary
# Generated: $(date)
# Location: $RANGES_DIR

## Range Files:
- aws_ec2_ranges.txt: $(wc -l < aws_ec2_ranges.txt) AWS EC2 ranges
- gcp_ranges.txt: $(wc -l < gcp_ranges.txt) Google Cloud ranges  
- cloudflare_v4.txt: $(wc -l < cloudflare_v4.txt) Cloudflare IPv4 ranges
- azure_ranges.txt: $(wc -l < azure_ranges.txt) Microsoft Azure ranges

## Usage:
These files are used by the Ante reconnaissance system for cloud provider
identification during Phase 7 (Cloud Infrastructure Analysis).

## Updates:
Run this script periodically to maintain current IP ranges.
Cloud providers update their ranges regularly.

## Notes:
- Requires 'jq' for optimal parsing (install: apt install jq)
- Falls back to known ranges if downloads fail
- Some ranges may overlap between providers
SUMMARY

# Calculate total ranges
TOTAL_RANGES=$(( $(wc -l < aws_ec2_ranges.txt) + $(wc -l < gcp_ranges.txt) + $(wc -l < cloudflare_v4.txt) + $(wc -l < azure_ranges.txt) ))

echo -e "\n${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    Update Complete                           ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${BLUE}SUMMARY:${NC}"
echo -e "📁 Location: ${CYAN}$RANGES_DIR${NC}"
echo -e "📊 Total Ranges: ${CYAN}$TOTAL_RANGES${NC}"
echo -e "🔄 Updated: ${CYAN}$(date)${NC}"

echo -e "\n${BLUE}FILES CREATED:${NC}"
ls -la "$RANGES_DIR"/*.txt | while read -r line; do
    filename=$(echo "$line" | awk '{print $9}' | xargs basename)
    size=$(echo "$line" | awk '{print $5}')
    echo -e "  ${CYAN}$filename${NC} (${size} bytes)"
done

echo -e "\n${YELLOW}RECOMMENDATIONS:${NC}"
echo -e "• Run this updater monthly to maintain current ranges"
echo -e "• Install 'jq' for better JSON parsing: ${CYAN}apt install jq${NC}"
echo -e "• Check range_summary.txt for detailed statistics"

if ! command -v jq >/dev/null 2>&1; then
    echo -e "\n${YELLOW}NOTE: 'jq' not found - using fallback ranges where needed${NC}"
fi

echo -e "\n${GREEN}Cloud provider IP ranges updated successfully!${NC}" | wc -l)
        TOTAL_RANGES=$((TOTAL_RANGES + count))
    fi
done

echo -e "\n${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║            Comprehensive Update Complete                     ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${BLUE}SUMMARY:${NC}"
echo -e "📁 Location: ${CYAN}$RANGES_DIR${NC}"
echo -e "📊 Total Ranges: ${CYAN}$TOTAL_RANGES${NC}"
echo -e "🔄 Updated: ${CYAN}$(date)${NC}"

echo -e "\n${BLUE}MAJOR CLOUD PROVIDERS:${NC}"
echo -e "  ${CYAN}AWS:${NC} $(wc -l < aws_ec2_ranges.txt) ranges"
echo -e "  ${CYAN}Azure:${NC} $(grep -v '^#' azure_ranges.txt | wc -l) ranges"  
echo -e "  ${CYAN}GCP:${NC} $(wc -l < gcp_ranges.txt) ranges"
echo -e "  ${CYAN}Oracle:${NC} $(grep -v '^#' oracle_ranges.txt | wc -l) ranges"

echo -e "\n${BLUE}CDN NETWORKS:${NC}"
echo -e "  ${CYAN}Cloudflare:${NC} $(wc -l < cloudflare_v4.txt) ranges"
echo -e "  ${CYAN}Fastly:${NC} $(grep -v '^#' fastly_ranges.txt | wc -l) ranges"
echo -e "  ${CYAN}Akamai:${NC} $(grep -v '^#' akamai_ranges.txt | wc -l) ranges"

echo -e "\n${BLUE}OTHER PROVIDERS:${NC}"
echo -e "  ${CYAN}DigitalOcean:${NC} $(grep -v '^#' digitalocean_ranges.txt | wc -l) ranges"
echo -e "  ${CYAN}Alibaba Cloud:${NC} $(grep -v '^#' alibaba_ranges.txt | wc -l) ranges"
echo -e "  ${CYAN}Vultr:${NC} $(grep -v '^#' vultr_ranges.txt | wc -l) ranges"

echo -e "\n${YELLOW}RECOMMENDATIONS:${NC}"
echo -e "• Update ranges weekly during active campaigns"
echo -e "• Install 'jq' for optimal parsing: ${CYAN}apt install jq${NC}"
echo -e "• Review range_summary.txt for detailed statistics"
echo -e "• Monitor provider documentation for API changes"

if ! command -v jq >/dev/null 2>&1; then
    echo -e "\n${YELLOW}NOTE: 'jq' not found - using fallback ranges where needed${NC}"
    echo -e "Install jq for better accuracy: ${CYAN}sudo apt install jq${NC}"
fi

echo -e "\n${GREEN}Comprehensive cloud provider ranges updated successfully!${NC}"
echo -e "${GREEN}Coverage now includes major cloud providers, CDNs, and edge networks.${NC}" -s -f > azure-ranges.json 2>/dev/null; then
    if command -v jq >/dev/null 2>&1; then
        if jq -r '.values[] | select(.name == "AzureCloud") | .properties.addressPrefixes[] | select(test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+$"))' azure-ranges.json > azure_ranges.txt 2>/dev/null; then
            AZURE_COUNT=$(wc -l < azure_ranges.txt)
            download_status "Azure" "success" "$AZURE_COUNT"
        else
            # Fallback for Azure
            echo "# Azure IP ranges (fallback)" > azure_ranges.txt
            echo "13.64.0.0/11" >> azure_ranges.txt
            echo "20.0.0.0/8" >> azure_ranges.txt
            echo "40.64.0.0/10" >> azure_ranges.txt
            echo "52.0.0.0/8" >> azure_ranges.txt
            echo "104.40.0.0/13" >> azure_ranges.txt
            download_status "Azure" "parse_error" "5"
        fi
    else
        echo "# Azure IP ranges (no jq available)" > azure_ranges.txt
        echo "13.64.0.0/11" >> azure_ranges.txt
        echo "20.0.0.0/8" >> azure_ranges.txt
        echo "40.64.0.0/10" >> azure_ranges.txt
        download_status "Azure" "parse_error" "3"
    fi
else
    # Basic Azure fallback ranges
    echo "# Azure IP ranges (download failed)" > azure_ranges.txt
    echo "13.64.0.0/11" >> azure_ranges.txt
    echo "20.0.0.0/8" >> azure_ranges.txt
    echo "40.64.0.0/10" >> azure_ranges.txt
    echo "52.0.0.0/8" >> azure_ranges.txt
    download_status "Azure" "error" "4"
fi

# Create summary report
echo -e "\n${YELLOW}[*] Creating range summary...${NC}"
cat > range_summary.txt << SUMMARY
# Cloud Provider IP Range Summary
# Generated: $(date)
# Location: $RANGES_DIR

## Range Files:
- aws_ec2_ranges.txt: $(wc -l < aws_ec2_ranges.txt) AWS EC2 ranges
- gcp_ranges.txt: $(wc -l < gcp_ranges.txt) Google Cloud ranges  
- cloudflare_v4.txt: $(wc -l < cloudflare_v4.txt) Cloudflare IPv4 ranges
- azure_ranges.txt: $(wc -l < azure_ranges.txt) Microsoft Azure ranges

## Usage:
These files are used by the Ante reconnaissance system for cloud provider
identification during Phase 7 (Cloud Infrastructure Analysis).

## Updates:
Run this script periodically to maintain current IP ranges.
Cloud providers update their ranges regularly.

## Notes:
- Requires 'jq' for optimal parsing (install: apt install jq)
- Falls back to known ranges if downloads fail
- Some ranges may overlap between providers
SUMMARY

# Calculate total ranges
TOTAL_RANGES=$(( $(wc -l < aws_ec2_ranges.txt) + $(wc -l < gcp_ranges.txt) + $(wc -l < cloudflare_v4.txt) + $(wc -l < azure_ranges.txt) ))

echo -e "\n${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    Update Complete                           ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${BLUE}SUMMARY:${NC}"
echo -e "📁 Location: ${CYAN}$RANGES_DIR${NC}"
echo -e "📊 Total Ranges: ${CYAN}$TOTAL_RANGES${NC}"
echo -e "🔄 Updated: ${CYAN}$(date)${NC}"

echo -e "\n${BLUE}FILES CREATED:${NC}"
ls -la "$RANGES_DIR"/*.txt | while read -r line; do
    filename=$(echo "$line" | awk '{print $9}' | xargs basename)
    size=$(echo "$line" | awk '{print $5}')
    echo -e "  ${CYAN}$filename${NC} (${size} bytes)"
done

echo -e "\n${YELLOW}RECOMMENDATIONS:${NC}"
echo -e "• Run this updater monthly to maintain current ranges"
echo -e "• Install 'jq' for better JSON parsing: ${CYAN}apt install jq${NC}"
echo -e "• Check range_summary.txt for detailed statistics"

if ! command -v jq >/dev/null 2>&1; then
    echo -e "\n${YELLOW}NOTE: 'jq' not found - using fallback ranges where needed${NC}"
fi

echo -e "\n${GREEN}Cloud provider IP ranges updated successfully!${NC}"