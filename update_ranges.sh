#!/bin/bash
# Cloud IP Range Updater

echo "🌐 Updating Cloud Provider IP Ranges"
echo "===================================="

RANGES_DIR="$HOME/ante_recon/cloud_ranges"
mkdir -p "$RANGES_DIR"
cd "$RANGES_DIR"

echo "Downloading AWS IP ranges..."
if curl -s https://ip-ranges.amazonaws.com/ip-ranges.json -o aws-ip-ranges.json; then
    jq -r '.prefixes[] | select(.service=="EC2") | .ip_prefix' aws-ip-ranges.json > aws_ec2_ranges.txt 2>/dev/null || {
        echo "jq parsing failed, creating minimal AWS ranges"
        echo "54.239.0.0/16" > aws_ec2_ranges.txt
        echo "52.0.0.0/8" >> aws_ec2_ranges.txt
    }
    echo "✅ AWS ranges: $(wc -l < aws_ec2_ranges.txt) entries"
else
    echo "❌ AWS download failed"
fi

echo "Downloading GCP IP ranges..."
if curl -s https://www.gstatic.com/ipranges/cloud.json -o gcp-cloud.json; then
    jq -r '.prefixes[].ipv4Prefix | select(. != null)' gcp-cloud.json > gcp_ranges.txt 2>/dev/null || {
        echo "jq parsing failed, creating minimal GCP ranges"
        echo "35.199.0.0/16" > gcp_ranges.txt
        echo "34.0.0.0/8" >> gcp_ranges.txt
    }
    echo "✅ GCP ranges: $(wc -l < gcp_ranges.txt) entries"
else
    echo "❌ GCP download failed"
fi

echo "Downloading Cloudflare IP ranges..."
if curl -s https://www.cloudflare.com/ips-v4 -o cloudflare_v4.txt; then
    echo "✅ Cloudflare ranges: $(wc -l < cloudflare_v4.txt) entries"
else
    echo "❌ Cloudflare download failed"
fi

echo ""
echo "✅ Cloud range update complete!"
echo "Files saved to: $RANGES_DIR"
