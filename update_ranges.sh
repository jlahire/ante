#!/bin/bash

# Simple script to update cloud IP ranges and VirusTotal scan lists
# Creates cloud_ranges directory and fetches latest IP ranges

set -e

# Check if cloud_ranges directory exists, create if not
if [ ! -d "cloud_ranges" ]; then
    echo "Creating cloud_ranges directory..."
    mkdir -p cloud_ranges
else
    echo "Found cloud_ranges directory"
fi

cd cloud_ranges

echo "Updating AWS IP ranges..."
curl -s https://ip-ranges.amazonaws.com/ip-ranges.json -o aws-ip-ranges.json
jq -r '.prefixes[] | select(.service=="EC2") | .ip_prefix' aws-ip-ranges.json > aws_ec2_ranges.txt
echo "AWS ranges: $(wc -l < aws_ec2_ranges.txt) networks"

echo "Updating GCP IP ranges..."
curl -s https://www.gstatic.com/ipranges/cloud.json -o gcp-cloud.json
jq -r '.prefixes[].ipv4Prefix | select(. != null)' gcp-cloud.json > gcp_ranges.txt
echo "GCP ranges: $(wc -l < gcp_ranges.txt) networks"

echo "Updating Cloudflare IPv4 ranges..."
curl -s https://www.cloudflare.com/ips-v4 > cloudflare_v4.txt
echo "Cloudflare IPv4 ranges: $(wc -l < cloudflare_v4.txt) networks"

echo "Updating VirusTotal scan ranges..."
# VirusTotal uses Google Cloud infrastructure
curl -s https://www.gstatic.com/ipranges/goog.json -o virustotal-ranges.json
jq -r '.prefixes[].ipv4Prefix | select(. != null)' virustotal-ranges.json > virustotal_ranges.txt
echo "VirusTotal ranges: $(wc -l < virustotal_ranges.txt) networks"

cd ..

echo "Cloud IP ranges and VirusTotal ranges updated successfully"
echo "Files created in cloud_ranges/:"
ls -la cloud_ranges/

echo ""
echo "Usage: Run this script in the same directory as your reconnaissance script"
echo "The ranges will be automatically detected and used during cloud analysis"