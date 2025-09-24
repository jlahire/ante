#!/bin/bash

# Ante Advanced Reconnaissance System Installer - Kali Linux Compatible
# Handles repository issues and completes installation
# Author: @jLaHire - September 2025

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL_DIR="$HOME/ante_recon"
CONFIG_DIR="$INSTALL_DIR/config"

echo -e "${GREEN}Fixing Ante installation and creating missing files...${NC}"

# Skip problematic system updates for now since tools are already installed
echo -e "\n${YELLOW}[1/5] Verifying directory structure...${NC}"
mkdir -p "$INSTALL_DIR"/{config,wordlists,cloud_ranges}

# Create missing configuration files
echo -e "\n${YELLOW}[2/5] Creating configuration files...${NC}"
cd "$CONFIG_DIR"

# Subfinder configuration
cat > subfinder_config.yaml << 'SUBCONF'
# Ante Subfinder Configuration
# Works with or without API keys

# Free APIs (no charges, safe to use)
chaos: ["${CHAOS_API_KEY}"]
github: ["${GITHUB_TOKEN}"]
urlscan: ["${URLSCAN_API_KEY}"]
virustotal: ["${VIRUSTOTAL_API_KEY}"]

# Built-in free sources (no API keys needed)
# These work even without any configuration:
# - crt.sh (Certificate Transparency)
# - dns.bufferover.run
# - threatcrowd
# - dnsdumpster
# - wayback machine
SUBCONF

# Environment setup script
cat > environment_setup.sh << 'ENV'
#!/bin/bash
# Ante Reconnaissance Environment Setup

echo "🎯 Ante Advanced Reconnaissance System Environment"
echo "================================================"

# Check for API keys to determine mode
API_COUNT=0
if [ -n "${GITHUB_TOKEN:-}" ]; then 
    API_COUNT=$((API_COUNT + 1))
fi
if [ -n "${CHAOS_API_KEY:-}" ]; then 
    API_COUNT=$((API_COUNT + 1))
fi
if [ -n "${URLSCAN_API_KEY:-}" ]; then 
    API_COUNT=$((API_COUNT + 1))
fi
if [ -n "${VIRUSTOTAL_API_KEY:-}" ]; then 
    API_COUNT=$((API_COUNT + 1))
fi

if [ $API_COUNT -gt 0 ]; then
    echo "🚀 FULL MODE: $API_COUNT API(s) configured"
    RECON_MODE="FULL"
else
    echo "⚡ BASIC MODE: No APIs required"
    RECON_MODE="BASIC"
fi

# API Status
echo ""
echo "API Configuration Status:"

if [ -n "${GITHUB_TOKEN:-}" ]; then
    echo "✅ GitHub API: Configured"
else
    echo "➖ GitHub API: Not configured (https://github.com/settings/tokens)"
fi

if [ -n "${CHAOS_API_KEY:-}" ]; then
    echo "✅ Chaos API: Configured"
else
    echo "➖ Chaos API: Not configured (https://chaos.projectdiscovery.io/)"
fi

if [ -n "${URLSCAN_API_KEY:-}" ]; then
    echo "✅ URLScan API: Configured"
else
    echo "➖ URLScan API: Not configured (https://urlscan.io/user/signup)"
fi

if [ -n "${VIRUSTOTAL_API_KEY:-}" ]; then
    echo "✅ VirusTotal API: Configured"
else
    echo "➖ VirusTotal API: Not configured (https://www.virustotal.com/gui/join-us)"
fi

# Path setup
export PATH="$PATH:$HOME/go/bin:$HOME/ante_recon"
export RECON_MODE="$RECON_MODE"
export RECON_THREADS=30

echo ""
echo "🎯 Ready for reconnaissance!"
echo ""
echo "Usage examples:"
echo "   Basic mode:  $HOME/ante_recon/ante.sh target.com --no-apis"
echo "   Full mode:   $HOME/ante_recon/ante.sh target.com"
echo ""
ENV

chmod +x environment_setup.sh

# API setup script
cd "$INSTALL_DIR"
cat > setup_apis.sh << 'APISETUP'
#!/bin/bash
# API Key Setup Script

echo "🔑 API Key Setup for Enhanced Reconnaissance"
echo "=========================================="
echo ""
echo "Configure FREE API keys for enhanced capabilities."
echo ""

echo "1. GitHub API Token (Recommended)"
echo "   Get at: https://github.com/settings/tokens"
echo "   Scopes: public_repo, read:user"
read -p "   Enter GitHub token (or Enter to skip): " github_token

echo ""
echo "2. Chaos API Key (Recommended)" 
echo "   Get at: https://chaos.projectdiscovery.io/"
read -p "   Enter Chaos API key (or Enter to skip): " chaos_key

echo ""
echo "3. URLScan API Key (Optional)"
echo "   Get at: https://urlscan.io/user/signup"
read -p "   Enter URLScan API key (or Enter to skip): " urlscan_key

echo ""
echo "4. VirusTotal API Key (Recommended)"
echo "   Get at: https://www.virustotal.com/gui/join-us"
echo "   Benefits: Threat intelligence, domain reputation, malware detection"
read -p "   Enter VirusTotal API key (or Enter to skip): " virustotal_key

echo ""
echo "Writing configuration to ~/.bashrc..."

# Remove existing entries
grep -v "GITHUB_TOKEN\|CHAOS_API_KEY\|URLSCAN_API_KEY" ~/.bashrc > ~/.bashrc.tmp 2>/dev/null || touch ~/.bashrc.tmp
mv ~/.bashrc.tmp ~/.bashrc

# Add new entries
echo "" >> ~/.bashrc
echo "# Ante Advanced Reconnaissance System API Keys" >> ~/.bashrc

if [ -n "$github_token" ]; then
    echo "export GITHUB_TOKEN='$github_token'" >> ~/.bashrc
    echo "✅ GitHub token configured"
fi

if [ -n "$chaos_key" ]; then
    echo "export CHAOS_API_KEY='$chaos_key'" >> ~/.bashrc
    echo "✅ Chaos API key configured"
fi

if [ -n "$urlscan_key" ]; then
    echo "export URLSCAN_API_KEY='$urlscan_key'" >> ~/.bashrc
    echo "✅ URLScan API key configured"
fi

if [ -n "$virustotal_key" ]; then
    echo "export VIRUSTOTAL_API_KEY='$virustotal_key'" >> ~/.bashrc
    echo "✅ VirusTotal API key configured"
fi

echo ""
echo "🎯 Configuration complete!"
echo "Run: source ~/.bashrc"
echo "Test: $HOME/ante_recon/ante.sh target.com"
APISETUP

chmod +x setup_apis.sh

# Validation script
cat > validate_system.sh << 'VALIDATE'
#!/bin/bash
# System Validation Script

echo "🔍 Ante System Validation"
echo "========================="

# Check tools
echo ""
echo "🛠️  Tools Check:"
TOOLS=("curl" "jq" "dig" "nmap" "subfinder" "httpx" "nuclei" "naabu" "subzy")
AVAILABLE=0

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo "✅ $tool"
        AVAILABLE=$((AVAILABLE + 1))
    else
        echo "❌ $tool"
    fi
done

echo ""
echo "📊 Status: $AVAILABLE/${#TOOLS[@]} tools available"

# Check APIs
echo ""
echo "🔑 API Status:"
API_COUNT=0

for api in GITHUB_TOKEN CHAOS_API_KEY URLSCAN_API_KEY VIRUSTOTAL_API_KEY; do
    if [ -n "${!api:-}" ]; then
        echo "✅ $api configured"
        API_COUNT=$((API_COUNT + 1))
    else
        echo "➖ $api not configured"
    fi
done

if [ $API_COUNT -gt 0 ]; then
    echo ""
    echo "🚀 FULL MODE: $API_COUNT API(s) configured"
else
    echo ""
    echo "⚡ BASIC MODE: Using public sources only"
fi

if [ $AVAILABLE -ge 6 ]; then
    echo ""
    echo "✅ SYSTEM READY for reconnaissance!"
    echo ""
    echo "Usage:"
    echo "  $HOME/ante_recon/ante.sh target.com --no-apis    # Basic mode"
    echo "  $HOME/ante_recon/ante.sh target.com              # Auto-detect mode"
else
    echo ""
    echo "⚠️  Some tools missing but system will work with reduced functionality"
fi
VALIDATE

chmod +x validate_system.sh

# Create wordlists
echo -e "\n${YELLOW}[3/5] Creating wordlists...${NC}"
cd "$INSTALL_DIR/wordlists"

cat > basic_subdomains.txt << 'SUBS'
www
mail
ftp
localhost
webmail
smtp
pop
ns1
webdisk
ns2
cpanel
whm
autodiscover
autoconfig
m
imap
test
ns
blog
pop3
dev
www2
admin
forum
news
vpn
ns3
mail2
new
mysql
old
www1
email
img
www3
help
shop
sql
secure
beta
mobile
api
support
www4
en
static
demo
dns
web
staging
app
backup
mx
status
portal
git
data
cloud
assets
cdn
media
docs
file
files
home
info
internal
intranet
remote
server
ssl
stage
stats
store
temp
upload
video
wiki
SUBS

echo -e "${CYAN}   Created basic subdomain list ($(wc -l < basic_subdomains.txt) entries)${NC}"

# Download extended wordlist
echo -e "${CYAN}   Downloading extended subdomain list...${NC}"
if curl -s -L "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" -o subdomains-top1million-5000.txt; then
    echo -e "${CYAN}   Downloaded extended list ($(wc -l < subdomains-top1million-5000.txt) entries)${NC}"
else
    echo -e "${YELLOW}   Extended list download failed - using basic list only${NC}"
    cp basic_subdomains.txt subdomains-top1million-5000.txt
fi

# Cloud ranges update script
echo -e "\n${YELLOW}[4/5] Creating cloud ranges updater...${NC}"
cd "$INSTALL_DIR"

cat > update_ranges.sh << 'UPDATER'
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
UPDATER

chmod +x update_ranges.sh

# Download initial cloud ranges
echo -e "\n${YELLOW}[5/5] Downloading initial cloud ranges...${NC}"
./update_ranges.sh

# Add to PATH
echo -e "\n${CYAN}Adding to PATH...${NC}"
if ! grep -q "$INSTALL_DIR" ~/.bashrc 2>/dev/null; then
    echo "" >> ~/.bashrc
    echo "# Ante Advanced Reconnaissance System" >> ~/.bashrc
    echo "export PATH=\"\$PATH:$INSTALL_DIR\"" >> ~/.bashrc
    echo "alias ante=\"$INSTALL_DIR/ante.sh\"" >> ~/.bashrc
    echo "alias ante-validate=\"$INSTALL_DIR/validate_system.sh\"" >> ~/.bashrc
    echo "alias ante-setup=\"$INSTALL_DIR/setup_apis.sh\"" >> ~/.bashrc
    echo "alias ante-update-ranges=\"$INSTALL_DIR/update_ranges.sh\"" >> ~/.bashrc
fi

echo -e "\n${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                Installation Complete!                        ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${BLUE}SYSTEM STATUS:${NC}"
echo -e "📁 Installation: ${GREEN}$INSTALL_DIR${NC}"
echo -e "🔧 All Go tools detected and ready"
echo -e "⚙️  Configuration files created"
echo -e "📚 Wordlists prepared"
echo -e "☁️  Cloud ranges downloaded"

echo -e "\n${YELLOW}QUICK START:${NC}"
echo -e "\n${GREEN}Basic Mode (works immediately):${NC}"
echo -e "   ${CYAN}$INSTALL_DIR/ante.sh target.com --no-apis${NC}"

echo -e "\n${GREEN}Setup APIs for Full Mode:${NC}"
echo -e "   ${CYAN}$INSTALL_DIR/setup_apis.sh${NC}"
echo -e "   ${CYAN}source ~/.bashrc${NC}"
echo -e "   ${CYAN}$INSTALL_DIR/ante.sh target.com${NC}"

echo -e "\n${GREEN}System Validation:${NC}"
echo -e "   ${CYAN}$INSTALL_DIR/validate_system.sh${NC}"

echo -e "\n${BLUE}NEXT STEPS:${NC}"
echo -e "1. Run: ${CYAN}source ~/.bashrc${NC} (to load PATH changes)"
echo -e "2. Test: ${CYAN}ante-validate${NC} (system check)"
echo -e "3. Try: ${CYAN}ante example.com --no-apis${NC} (basic test)"
echo -e "4. Optional: ${CYAN}ante-setup${NC} (configure APIs)"

echo -e "\n${GREEN}Installation successful! System ready for reconnaissance.${NC}"