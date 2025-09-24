#!/bin/bash

# Ante Advanced Reconnaissance System Installer
# Supports both API-enabled and API-free reconnaissance
# Author: @jLaHire
# Release Date: September 22, 2025

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL_DIR="$HOME/ante_recon"
TOOLS_DIR="$INSTALL_DIR/tools"
CONFIG_DIR="$INSTALL_DIR/config"

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                Ante - Advanced Reconnaissance                ║${NC}"
echo -e "${BLUE}║              Works with OR without API keys                  ║${NC}"
echo -e "${BLUE}║                    Author: @jLaHire                          ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${YELLOW}This installer provides TWO reconnaissance modes:${NC}"
echo ""
echo -e "${GREEN}1. BASIC MODE (No API keys required):${NC}"
echo -e "   • Certificate transparency scanning"
echo -e "   • DNS enumeration and brute forcing"  
echo -e "   • Live host detection and port scanning"
echo -e "   • Web technology identification"
echo -e "   • Vulnerability scanning"
echo -e "   • Professional reporting"
echo ""
echo -e "${CYAN}2. FULL MODE (Free API keys enhance capabilities):${NC}"
echo -e "   • All Basic Mode features PLUS:"
echo -e "   • Enhanced subdomain discovery"
echo -e "   • GitHub dorking for sensitive data"
echo -e "   • Microsoft/Office365 enumeration"
echo -e "   • Advanced threat intelligence"
echo ""
echo -e "${YELLOW}Both modes provide professional-grade reconnaissance!${NC}"

read -p "Continue with installation? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Installation cancelled."
    exit 1
fi

# Create directory structure
echo -e "\n${YELLOW}[1/6] Creating directory structure...${NC}"
mkdir -p "$INSTALL_DIR" "$TOOLS_DIR" "$CONFIG_DIR"
mkdir -p "$INSTALL_DIR"/{wordlists,cloud_ranges,templates}

# System dependencies
echo -e "\n${YELLOW}[2/6] Installing system dependencies...${NC}"
echo -e "${CYAN}   Installing essential tools (dig, nmap, curl, jq)...${NC}"

if command -v apt-get &> /dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq git python3 python3-pip golang-go curl wget jq \
        whois dnsutils nmap build-essential openssl >/dev/null 2>&1
elif command -v yum &> /dev/null; then
    sudo yum install -y -q git python3 python3-pip golang curl wget jq \
        whois bind-utils nmap gcc openssl >/dev/null 2>&1
elif command -v brew &> /dev/null; then
    brew install git python3 go curl wget jq whois nmap openssl >/dev/null 2>&1
else
    echo -e "${RED}Unsupported package manager. Install dependencies manually.${NC}"
    echo "Required: git python3 golang curl wget jq whois nmap openssl"
    exit 1
fi

# Go environment setup
echo -e "\n${YELLOW}[3/6] Setting up Go environment...${NC}"
if ! command -v go &> /dev/null; then
    echo -e "${CYAN}   Installing Go programming language...${NC}"
    GO_VERSION="1.21.5"
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        wget -q "https://go.dev/dl/go${GO_VERSION}.darwin-amd64.tar.gz" -O /tmp/go.tar.gz
    else
        wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    fi
    
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz >/dev/null 2>&1
    rm /tmp/go.tar.gz
fi

export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
if ! grep -q "/usr/local/go/bin" ~/.bashrc 2>/dev/null; then
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
fi

# Install reconnaissance tools
echo -e "\n${YELLOW}[4/6] Installing reconnaissance tools...${NC}"

# Essential tools for basic mode
echo -e "${CYAN}   Installing core reconnaissance tools...${NC}"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest >/dev/null 2>&1 &
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest >/dev/null 2>&1 &
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest >/dev/null 2>&1 &

# Additional tools for enhanced capabilities
echo -e "${CYAN}   Installing additional tools...${NC}"
go install -v github.com/projectdiscovery/katana/cmd/katana@latest >/dev/null 2>&1 &
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest >/dev/null 2>&1 &
go install -v github.com/tomnomnom/assetfinder@latest >/dev/null 2>&1 &

wait  # Wait for all installs to complete

# Initialize nuclei templates
echo -e "${CYAN}   Updating vulnerability templates...${NC}"
nuclei -update-templates -silent >/dev/null 2>&1 || true

# Python tools for specific enumerations
echo -e "${CYAN}   Installing Python analysis tools...${NC}"
pip3 install --user -q requests beautifulsoup4 dnspython 2>/dev/null || true

# Download essential wordlists
echo -e "\n${YELLOW}[5/6] Setting up wordlists and data...${NC}"
cd "$INSTALL_DIR/wordlists"

echo -e "${CYAN}   Downloading subdomain wordlists...${NC}"
wget -q -O subdomains-top1million-5000.txt "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" || touch subdomains-top1million-5000.txt

# Create basic subdomain list for DNS brute forcing
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
ftp2
home
info
internal
intranet
linux
mail1
mail3
remote
server
ssl
stage
stats
store
temp
test1
test2
upload
video
wiki
SUBS

# Configuration files
echo -e "\n${YELLOW}[6/6] Creating configuration files...${NC}"
cd "$CONFIG_DIR"

# Ante environment configuration
cat > environment_setup.sh << 'ENV'
#!/bin/bash
# Ante Reconnaissance Environment Setup
# Supports both Basic and Full modes

echo "🎯 Ante Advanced Reconnaissance System Environment"
echo "================================================"

# =================
# MODE SELECTION
# =================

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

if [ $API_COUNT -gt 0 ]; then
    echo "🚀 FULL MODE: $API_COUNT API(s) configured"
    RECON_MODE="FULL"
else
    echo "⚡ BASIC MODE: No APIs required"
    RECON_MODE="BASIC"
fi

# =================
# API CONFIGURATION (OPTIONAL)
# =================

echo ""
echo "API Configuration Status:"

# GitHub Token (FREE - Unlimited for public repos)
if [ -n "${GITHUB_TOKEN:-}" ]; then
    echo "✅ GitHub API: Configured (Enhanced subdomain discovery + sensitive data search)"
else
    echo "➖ GitHub API: Not configured"
    echo "   Get free at: https://github.com/settings/tokens"
    echo "   Benefits: GitHub dorking, enhanced discovery"
fi

# Chaos API (FREE - No charges)
if [ -n "${CHAOS_API_KEY:-}" ]; then
    echo "✅ Chaos API: Configured (ProjectDiscovery subdomain database)"
else
    echo "➖ Chaos API: Not configured"
    echo "   Get free at: https://chaos.projectdiscovery.io/"
    echo "   Benefits: Massive subdomain database access"
fi

# URLScan API (FREE - 1000/day)
if [ -n "${URLSCAN_API_KEY:-}" ]; then
    echo "✅ URLScan API: Configured (Web page analysis)"
else
    echo "➖ URLScan API: Not configured"
    echo "   Get free at: https://urlscan.io/user/signup"
    echo "   Benefits: Advanced web analysis"
fi

# =================
# TOOL CONFIGURATION
# =================

# Path setup
export PATH="$PATH:$HOME/go/bin:$HOME/ante_recon/tools"

# Reconnaissance settings
export RECON_MODE="$RECON_MODE"
export RECON_THREADS=30
export RECON_DELAY=1
export MAX_SUBDOMAINS_PER_DOMAIN=2000

# Tool configurations
export SUBFINDER_CONFIG="$HOME/ante_recon/config/subfinder_config.yaml"

echo ""
echo "🛠️  System Configuration:"
echo "   Mode: $RECON_MODE"
echo "   Threads: $RECON_THREADS"
echo "   Wordlists: Available"
echo "   Tools: Go-based reconnaissance suite"

echo ""
echo "🎯 Ready for reconnaissance!"
echo ""
echo "Usage examples:"
echo "   Basic mode:  ./ante.sh target.com --no-apis"
echo "   Full mode:   ./ante.sh target.com"
echo "   Interactive: ./ante.sh target.com --api-mode"
echo ""

if [ "$RECON_MODE" = "BASIC" ]; then
    echo "💡 To enable Full Mode, add API keys:"
    echo "   export GITHUB_TOKEN='your_token_here'"
    echo "   export CHAOS_API_KEY='your_key_here'"
    echo "   source $HOME/ante_recon/config/environment_setup.sh"
fi
ENV

chmod +x environment_setup.sh

# Subfinder configuration supporting both modes
cat > subfinder_config.yaml << 'SUBCONF'
# Ante Subfinder Configuration
# Works with or without API keys

# Free APIs (no charges, safe to use)
chaos: ["${CHAOS_API_KEY}"]
github: ["${GITHUB_TOKEN}"]
urlscan: ["${URLSCAN_API_KEY}"]

# Built-in free sources (no API keys needed)
# These work even without any configuration:
# - crt.sh (Certificate Transparency)
# - dns.bufferover.run
# - threatcrowd
# - dnsdumpster
# - wayback machine
SUBCONF

# Create the main reconnaissance script wrapper
cd "$INSTALL_DIR"

cat > ante.sh << 'WRAPPER'
#!/bin/bash
# Ante Advanced Reconnaissance System Launcher

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ANTE_HOME="$HOME/ante_recon"

# Load environment
if [ -f "$ANTE_HOME/config/environment_setup.sh" ]; then
    source "$ANTE_HOME/config/environment_setup.sh" >/dev/null 2>&1
fi

# Check if domain provided
if [ $# -eq 0 ]; then
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                Ante - Advanced Reconnaissance                ║${NC}"
    echo -e "${BLUE}║              Works with OR without API keys                  ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo -e "${RED}Usage: $0 <domain> [options]${NC}"
    echo ""
    echo "Examples:"
    echo "  $0 tesla.com                    # Auto-detect mode"
    echo "  $0 tesla.com --no-apis          # Force basic mode"
    echo "  $0 tesla.com --api-mode         # Interactive setup"
    echo ""
    echo -e "${GREEN}Basic Mode (No APIs needed):${NC}"
    echo "  • Certificate transparency scanning"
    echo "  • DNS enumeration and brute forcing"
    echo "  • Live host detection and port scanning"
    echo "  • Web technology identification"
    echo "  • Vulnerability scanning with Nuclei"
    echo "  • Professional reporting"
    echo ""
    echo -e "${CYAN}Full Mode (Free APIs enhance results):${NC}"
    echo "  • All Basic Mode features PLUS:"
    echo "  • Enhanced subdomain discovery"
    echo "  • GitHub dorking for sensitive data"
    echo "  • Microsoft/Office365 enumeration"
    echo "  • Advanced threat intelligence"
    echo ""
    echo -e "${YELLOW}Setup API keys (optional but recommended):${NC}"
    echo "  GitHub: https://github.com/settings/tokens"
    echo "  Chaos:  https://chaos.projectdiscovery.io/"
    echo "  URLScan: https://urlscan.io/user/signup"
    exit 1
fi

# Check if main script exists
MAIN_SCRIPT="$ANTE_HOME/ante_main.sh"
if [ ! -f "$MAIN_SCRIPT" ]; then
    echo -e "${RED}Error: Main reconnaissance script not found.${NC}"
    echo "Expected: $MAIN_SCRIPT"
    echo ""
    echo "Please ensure the ante_main.sh script is in the installation directory."
    exit 1
fi

# Show current configuration
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    SYSTEM STATUS                             ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"

# Check tool availability
TOOLS_AVAILABLE=0
TOOLS_TOTAL=5

for tool in subfinder httpx nuclei nmap curl; do
    if command -v "$tool" &> /dev/null; then
        echo -e "✅ $tool available"
        TOOLS_AVAILABLE=$((TOOLS_AVAILABLE + 1))
    else
        echo -e "❌ $tool missing"
    fi
done

echo ""
echo -e "${YELLOW}Tools Status: $TOOLS_AVAILABLE/$TOOLS_TOTAL available${NC}"

if [ $TOOLS_AVAILABLE -lt 3 ]; then
    echo -e "${RED}Insufficient tools available. Please install missing tools.${NC}"
    exit 1
fi

# API Status
echo ""
echo -e "${BLUE}API Configuration:${NC}"
if [ -n "${GITHUB_TOKEN:-}" ]; then
    echo -e "✅ GitHub API configured"
fi
if [ -n "${CHAOS_API_KEY:-}" ]; then
    echo -e "✅ Chaos API configured"
fi
if [ -n "${URLSCAN_API_KEY:-}" ]; then
    echo -e "✅ URLScan API configured"
fi

API_COUNT=0
[ -n "${GITHUB_TOKEN:-}" ] && API_COUNT=$((API_COUNT + 1))
[ -n "${CHAOS_API_KEY:-}" ] && API_COUNT=$((API_COUNT + 1))
[ -n "${URLSCAN_API_KEY:-}" ] && API_COUNT=$((API_COUNT + 1))

if [ $API_COUNT -eq 0 ]; then
    echo -e "➖ No APIs configured (Basic Mode)"
    echo -e "${YELLOW}   System will work with public sources only${NC}"
else
    echo -e "${GREEN}   $API_COUNT API(s) configured (Full Mode)${NC}"
fi

echo ""
read -p "Continue with reconnaissance? (Y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Nn]$ ]]; then
    echo "Reconnaissance cancelled."
    exit 1
fi

# Execute main reconnaissance script
echo -e "${GREEN}Starting Ante reconnaissance...${NC}"
exec "$MAIN_SCRIPT" "$@"
WRAPPER

chmod +x ante.sh

# Create quick setup script for API keys
cat > setup_apis.sh << 'APISETUP'
#!/bin/bash
# Quick API Key Setup Script for Ante

echo "🔑 API Key Setup for Enhanced Reconnaissance"
echo "=========================================="
echo ""
echo "This script helps you configure FREE API keys for enhanced capabilities."
echo "All APIs listed here are free with no charges."
echo ""

# GitHub Setup
echo "1. GitHub API Token (Recommended)"
echo "   Benefits: Enhanced subdomain discovery, sensitive data search"
echo "   Get at: https://github.com/settings/tokens"
echo "   Scopes: Select 'public_repo' and 'read:user'"
echo ""
read -p "   Enter GitHub token (or press Enter to skip): " github_token

# Chaos Setup  
echo ""
echo "2. Chaos API Key (Recommended)"
echo "   Benefits: Access to ProjectDiscovery's subdomain database"
echo "   Get at: https://chaos.projectdiscovery.io/"
echo "   Sign up with GitHub for easy registration"
echo ""
read -p "   Enter Chaos API key (or press Enter to skip): " chaos_key

# URLScan Setup
echo ""
echo "3. URLScan API Key (Optional)"
echo "   Benefits: Advanced web page analysis and screenshots"
echo "   Get at: https://urlscan.io/user/signup"
echo "   Limit: 1000 scans per day (free)"
echo ""
read -p "   Enter URLScan API key (or press Enter to skip): " urlscan_key

# Write configuration
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

echo ""
echo "🎯 Configuration complete!"
echo ""
echo "To apply changes:"
echo "   source ~/.bashrc"
echo ""
echo "To test the system:"
echo "   source ~/.bashrc"
echo "   $HOME/ante_recon/ante.sh yourdomain.com"
echo ""
echo "Your system will now run in FULL MODE with enhanced capabilities!"
APISETUP

chmod +x setup_apis.sh

# Create validation script
cat > validate_system.sh << 'VALIDATE'
#!/bin/bash
# Ante System Validation Script

echo "🔍 Ante Advanced Reconnaissance System Validation"
echo "==============================================="

# Check directory structure
echo ""
echo "📁 Directory Structure:"
if [ -d "$HOME/ante_recon" ]; then
    echo "✅ Installation directory found"
    
    for dir in tools config wordlists; do
        if [ -d "$HOME/ante_recon/$dir" ]; then
            echo "✅ $dir directory exists"
        else
            echo "❌ $dir directory missing"
        fi
    done
else
    echo "❌ Installation directory not found"
    exit 1
fi

# Check essential tools
echo ""
echo "🛠️  Essential Tools:"
ESSENTIAL=("curl" "jq" "dig" "nmap" "openssl")
for tool in "${ESSENTIAL[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo "✅ $tool available"
    else
        echo "❌ $tool missing"
    fi
done

# Check Go tools
echo ""
echo "🔧 Go-based Tools:"
GO_TOOLS=("subfinder" "httpx" "nuclei" "katana" "naabu")
AVAILABLE_COUNT=0
for tool in "${GO_TOOLS[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo "✅ $tool available"
        AVAILABLE_COUNT=$((AVAILABLE_COUNT + 1))
    else
        echo "⚠️  $tool not available"
    fi
done

echo ""
echo "📊 Go Tools Status: $AVAILABLE_COUNT/${#GO_TOOLS[@]} available"

# Check API configuration
echo ""
echo "🔑 API Configuration:"
API_COUNT=0

if [ -n "${GITHUB_TOKEN:-}" ]; then
    echo "✅ GitHub API configured"
    API_COUNT=$((API_COUNT + 1))
else
    echo "➖ GitHub API not configured"
fi

if [ -n "${CHAOS_API_KEY:-}" ]; then
    echo "✅ Chaos API configured"
    API_COUNT=$((API_COUNT + 1))
else
    echo "➖ Chaos API not configured"
fi

if [ -n "${URLSCAN_API_KEY:-}" ]; then
    echo "✅ URLScan API configured"
    API_COUNT=$((API_COUNT + 1))
else
    echo "➖ URLScan API not configured"
fi

# Determine system mode
echo ""
echo "🎯 System Status:"
if [ $API_COUNT -gt 0 ]; then
    echo "✅ FULL MODE: $API_COUNT API(s) configured"
    echo "   Enhanced reconnaissance capabilities available"
else
    echo "⚡ BASIC MODE: No APIs configured"
    echo "   Professional reconnaissance using public sources only"
fi

if [ $AVAILABLE_COUNT -ge 3 ]; then
    echo "✅ SYSTEM READY: Sufficient tools available for reconnaissance"
    SYSTEM_READY=true
else
    echo "⚠️  SYSTEM INCOMPLETE: Install missing Go tools for full functionality"
    SYSTEM_READY=false
fi

# Usage recommendations
echo ""
echo "🚀 Usage Examples:"
echo ""
if [ $API_COUNT -gt 0 ]; then
    echo "Full reconnaissance (with APIs):"
    echo "   $HOME/ante_recon/ante.sh target.com"
    echo ""
fi

echo "Basic reconnaissance (no APIs needed):"
echo "   $HOME/ante_recon/ante.sh target.com --no-apis"
echo ""

if [ $API_COUNT -eq 0 ]; then
    echo "💡 To enable Full Mode:"
    echo "   $HOME/ante_recon/setup_apis.sh"
    echo ""
fi

if [ "$SYSTEM_READY" = false ]; then
    echo "🔧 To install missing tools:"
    echo "   go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    echo "   go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    echo "   go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
    echo ""
fi

echo "📋 System validation complete!"
VALIDATE

chmod +x validate_system.sh

# Final setup completion
echo -e "\n${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                Installation Complete!                        ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${BLUE}INSTALLED COMPONENTS:${NC}"
echo -e "📁 System location: ${GREEN}$INSTALL_DIR${NC}"
echo -e "🔧 Tools: subfinder, httpx, nuclei, katana, naabu, nmap, curl, jq"
echo -e "📚 Wordlists: Basic and advanced subdomain lists"
echo -e "⚙️  Configurations: Flexible API setup supporting both modes"

echo -e "\n${YELLOW}SYSTEM MODES:${NC}"
echo -e "\n${GREEN}1. BASIC MODE (Works immediately, no setup required):${NC}"
echo -e "   • Certificate transparency scanning"
echo -e "   • DNS enumeration and brute forcing"
echo -e "   • Live host detection and port scanning"
echo -e "   • Web technology identification"  
echo -e "   • Vulnerability scanning with Nuclei"
echo -e "   • Professional reporting and analysis"

echo -e "\n${CYAN}2. FULL MODE (Enhanced with free API keys):${NC}"
echo -e "   • All Basic Mode features PLUS:"
echo -e "   • Enhanced subdomain discovery via APIs"
echo -e "   • GitHub dorking for sensitive data"
echo -e "   • Microsoft/Office365 enumeration"
echo -e "   • Advanced threat intelligence"

echo -e "\n${BLUE}QUICK START (Choose your approach):${NC}"

echo -e "\n${YELLOW}Option A: Start immediately (Basic Mode):${NC}"
echo -e "   ${CYAN}$INSTALL_DIR/ante.sh target.com --no-apis${NC}"

echo -e "\n${YELLOW}Option B: Setup APIs first (Full Mode):${NC}"
echo -e "   ${CYAN}$INSTALL_DIR/setup_apis.sh${NC}"
echo -e "   ${CYAN}source ~/.bashrc${NC}"
echo -e "   ${CYAN}$INSTALL_DIR/ante.sh target.com${NC}"

echo -e "\n${YELLOW}Option C: Test system validation:${NC}"
echo -e "   ${CYAN}$INSTALL_DIR/validate_system.sh${NC}"

echo -e "\n${GREEN}FREE API KEYS (No charges, enhance capabilities):${NC}"
echo -e "🔑 GitHub Token: ${CYAN}https://github.com/settings/tokens${NC}"
echo -e "   • Select: public_repo, read:user"
echo -e "   • Benefits: GitHub dorking, enhanced discovery"

echo -e "\n🔑 Chaos API Key: ${CYAN}https://chaos.projectdiscovery.io/${NC}"
echo -e "   • Sign up with GitHub"
echo -e "   • Benefits: Massive subdomain database"

echo -e "\n🔑 URLScan API Key: ${CYAN}https://urlscan.io/user/signup${NC}"
echo -e "   • 1000 scans/day free"
echo -e "   • Benefits: Advanced web analysis"

echo -e "\n${BLUE}SYSTEM FEATURES:${NC}"
echo -e "• Automatically detects and adapts to available APIs"
echo -e "• Professional reporting in both Basic and Full modes"
echo -e "• No API keys required for immediate use"
echo -e "• Free APIs enhance capabilities without charges"
echo -e "• Comprehensive vulnerability scanning"
echo -e "• Docker-like progress display with time estimates"

echo -e "\n${RED}IMPORTANT REMINDERS:${NC}"
echo -e "• Only test domains you own or have explicit permission to assess"
echo -e "• All recommended APIs are free with no charges"
echo -e "• System works professionally even without any API keys"
echo -e "• Follow responsible disclosure for any vulnerabilities found"

# Add to PATH
if ! grep -q "$INSTALL_DIR" ~/.bashrc 2>/dev/null; then
    echo "" >> ~/.bashrc
    echo "# Ante Advanced Reconnaissance System" >> ~/.bashrc
    echo "export PATH=\"\$PATH:$INSTALL_DIR\"" >> ~/.bashrc
    echo "alias ante=\"$INSTALL_DIR/ante.sh\"" >> ~/.bashrc
    echo "alias ante-validate=\"$INSTALL_DIR/validate_system.sh\"" >> ~/.bashrc
    echo "alias ante-setup=\"$INSTALL_DIR/setup_apis.sh\"" >> ~/.bashrc
fi

echo -e "\n${GREEN}Installation successful! Ready for Ante reconnaissance.${NC}"

echo -e "\n${CYAN}Quick commands after reload:${NC}"
echo -e "  ante target.com              # Auto-detect mode"
echo -e "  ante target.com --no-apis    # Force basic mode"  
echo -e "  ante-validate                # Check system status"
echo -e "  ante-setup                   # Configure API keys"

echo -e "\n${YELLOW}Reload shell: source ~/.bashrc${NC}"