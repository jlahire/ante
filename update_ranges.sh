#!/bin/bash

# Cloud Provider IP Range Updater for Ante Reconnaissance System
# Downloads and maintains current IP ranges for cloud provider detection
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
echo -e "${BLUE}║           Cloud Provider IP Range Updater                   ║${NC}"
echo -e "${BLUE}║          Maintains current ranges for reconnaissance         ║${NC}"
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
        echo -e "${RED}[-] $service: Download failed${NC}"
    elif [ "$status" = "parse_error" ]; then
        echo -e "${YELLOW}[!] $service: Downloaded but parsing failed, using fallback${NC}"
    fi
}

echo -e "\n${CYAN}[1/4] Downloading AWS IP Ranges...${NC}"
if curl -s -f https://ip-ranges.amazonaws.com/ip-ranges.json -o aws-ip-ranges.json; then
    if command -v jq >/dev/null 2>&1; then
        if jq -r '.prefixes[] | select(.service=="EC2") | .ip_prefix' aws-ip-ranges.json > aws_ec2_ranges.txt 2>/dev/null; then
            AWS_COUNT=$(wc -l < aws_ec2_ranges.txt)
            download_status "AWS EC2" "success" "$AWS_COUNT"
        else
            # Fallback if jq parsing fails
            echo "# AWS EC2 IP ranges (fallback)" > aws_ec2_ranges.txt
            echo "54.239.0.0/16" >> aws_ec2_ranges.txt
            echo "52.0.0.0/8" >> aws_ec2_ranges.txt
            echo "34.192.0.0/10" >> aws_ec2_ranges.txt
            download_status "AWS EC2" "parse_error" "3"
        fi
    else
        # No jq available, use minimal fallback
        echo "# AWS EC2 IP ranges (no jq available)" > aws_ec2_ranges.txt
        echo "54.239.0.0/16" >> aws_ec2_ranges.txt
        echo "52.0.0.0/8" >> aws_ec2_ranges.txt
        download_status "AWS EC2" "parse_error" "2"
    fi
else
    echo "# AWS EC2 ranges unavailable" > aws_ec2_ranges.txt
    download_status "AWS EC2" "error" "0"
fi

echo -e "\n${CYAN}[2/4] Downloading Google Cloud Platform IP Ranges...${NC}"
if curl -s -f https://www.gstatic.com/ipranges/cloud.json -o gcp-cloud.json; then
    if command -v jq >/dev/null 2>&1; then
        if jq -r '.prefixes[].ipv4Prefix | select(. != null)' gcp-cloud.json > gcp_ranges.txt 2>/dev/null; then
            GCP_COUNT=$(wc -l < gcp_ranges.txt)
            download_status "GCP" "success" "$GCP_COUNT"
        else
            # Fallback if jq parsing fails
            echo "# GCP IP ranges (fallback)" > gcp_ranges.txt
            echo "35.199.0.0/16" >> gcp_ranges.txt
            echo "34.0.0.0/8" >> gcp_ranges.txt
            echo "104.196.0.0/14" >> gcp_ranges.txt
            download_status "GCP" "parse_error" "3"
        fi
    else
        # No jq available, use minimal fallback
        echo "# GCP IP ranges (no jq available)" > gcp_ranges.txt
        echo "35.199.0.0/16" >> gcp_ranges.txt
        echo "34.0.0.0/8" >> gcp_ranges.txt
        download_status "GCP" "parse_error" "2"
    fi
else
    echo "# GCP ranges unavailable" > gcp_ranges.txt
    download_status "GCP" "error" "0"
fi

echo -e "\n${CYAN}[3/4] Downloading Cloudflare IP Ranges...${NC}"
if curl -s -f https://www.cloudflare.com/ips-v4 -o cloudflare_v4.txt; then
    CF_COUNT=$(wc -l < cloudflare_v4.txt)
    download_status "Cloudflare" "success" "$CF_COUNT"
else
    # Fallback with known Cloudflare ranges
    echo "# Cloudflare IP ranges (fallback)" > cloudflare_v4.txt
    echo "173.245.48.0/20" >> cloudflare_v4.txt
    echo "103.21.244.0/22" >> cloudflare_v4.txt
    echo "103.22.200.0/22" >> cloudflare_v4.txt
    echo "103.31.4.0/22" >> cloudflare_v4.txt
    echo "141.101.64.0/18" >> cloudflare_v4.txt
    echo "108.162.192.0/18" >> cloudflare_v4.txt
    echo "190.93.240.0/20" >> cloudflare_v4.txt
    echo "188.114.96.0/20" >> cloudflare_v4.txt
    echo "197.234.240.0/22" >> cloudflare_v4.txt
    echo "198.41.128.0/17" >> cloudflare_v4.txt
    echo "162.158.0.0/15" >> cloudflare_v4.txt
    echo "104.16.0.0/13" >> cloudflare_v4.txt
    echo "104.24.0.0/14" >> cloudflare_v4.txt
    echo "172.64.0.0/13" >> cloudflare_v4.txt
    echo "131.0.72.0/22" >> cloudflare_v4.txt
    download_status "Cloudflare" "parse_error" "15"
fi

echo -e "\n${CYAN}[4/4] Downloading Azure IP Ranges...${NC}"
# Azure ranges are more complex and change frequently
# We'll attempt to get them but provide a basic fallback
if curl -s -f "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519" | grep -o 'https://[^"]*ServiceTags[^"]*\.json' | head -1 | xargs curl -s -f > azure-ranges.json 2>/dev/null; then
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