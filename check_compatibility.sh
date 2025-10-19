#!/bin/bash

# Enhanced Ante System Compatibility and Health Checker v2.0
# Validates all components including Smap and fixes common issues
# Author: @jLaHire - September 2025

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL_DIR="$HOME/ante_recon"

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║        Enhanced Ante System Compatibility Checker v2.0       ║${NC}"
echo -e "${BLUE}║       Validates components including Smap integration        ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"

# Function to check and report status
check_status() {
    local item="$1"
    local status="$2"
    local message="$3"
    
    if [ "$status" = "ok" ]; then
        echo -e "${GREEN}✅ $item${NC}"
    elif [ "$status" = "warning" ]; then
        echo -e "${YELLOW}⚠️  $item${NC}"
        [ -n "$message" ] && echo -e "   ${YELLOW}$message${NC}"
    else
        echo -e "${RED}❌ $item${NC}"
        [ -n "$message" ] && echo -e "   ${RED}$message${NC}"
    fi
}

# Check installation directory
echo -e "\n${CYAN}📁 Installation Directory Check${NC}"
if [ -d "$INSTALL_DIR" ]; then
    check_status "Installation directory" "ok"
    
    # Check subdirectories
    REQUIRED_DIRS=("config" "wordlists" "cloud_ranges")
    for dir in "${REQUIRED_DIRS[@]}"; do
        if [ -d "$INSTALL_DIR/$dir" ]; then
            check_status "$dir directory" "ok"
        else
            check_status "$dir directory" "error" "Missing - creating now..."
            mkdir -p "$INSTALL_DIR/$dir"
        fi
    done
else
    check_status "Installation directory" "error" "Not found at $INSTALL_DIR"
    echo -e "${YELLOW}Run the installer to create proper directory structure${NC}"
fi

# Check main script
echo -e "\n${CYAN}📝 Main Script Check${NC}"
if [ -f "$INSTALL_DIR/ante.sh" ]; then
    if [ -x "$INSTALL_DIR/ante.sh" ]; then
        check_status "ante.sh script" "ok"
    else
        check_status "ante.sh script" "warning" "Not executable - fixing..."
        chmod +x "$INSTALL_DIR/ante.sh"
    fi
else
    check_status "ante.sh script" "error" "Missing main reconnaissance script"
fi

# Check essential system tools
echo -e "\n${CYAN}🛠️  Essential System Tools Check${NC}"
ESSENTIAL_TOOLS=("curl" "jq" "dig" "nmap" "openssl" "whois" "python3")
MISSING_ESSENTIAL=()

for tool in "${ESSENTIAL_TOOLS[@]}"; do
    if command -v "$tool" &> /dev/null; then
        check_status "$tool" "ok"
    else
        check_status "$tool" "error" "Required system tool missing"
        MISSING_ESSENTIAL+=("$tool")
    fi
done

# Check enhanced Go tools with Smap
echo -e "\n${CYAN}🚀 Enhanced Go Tools Check (Including Smap)${NC}"
GO_TOOLS=("subfinder" "httpx" "nuclei" "katana" "naabu" "subzy" "smap")
AVAILABLE_GO_TOOLS=0
MISSING_GO_TOOLS=()
SMAP_AVAILABLE=false

for tool in "${GO_TOOLS[@]}"; do
    if command -v "$tool" &> /dev/null; then
        if [ "$tool" = "smap" ]; then
            check_status "$tool" "ok" "Shodan-powered passive scanning (200 hosts/sec)"
            SMAP_AVAILABLE=true
        else
            check_status "$tool" "ok"
        fi
        AVAILABLE_GO_TOOLS=$((AVAILABLE_GO_TOOLS + 1))
    else
        if [ "$tool" = "smap" ]; then
            check_status "$tool" "warning" "Shodan-powered passive scanning - HIGHLY RECOMMENDED"
        else
            check_status "$tool" "warning" "Optional tool not installed"
        fi
        MISSING_GO_TOOLS+=("$tool")
    fi
done

# Smap-specific capabilities check
if [ "$SMAP_AVAILABLE" = true ]; then
    echo -e "\n${CYAN}⚡ Smap Capabilities Verification${NC}"
    
    # Test Smap functionality
    if timeout 10 smap --help &> /dev/null; then
        check_status "Smap functionality" "ok" "Ready for passive reconnaissance"
    else
        check_status "Smap functionality" "warning" "Installed but may have issues"
    fi
    
    # Check Smap version and features
    SMAP_VERSION=$(smap --version 2>/dev/null || echo "unknown")
    if [ "$SMAP_VERSION" != "unknown" ]; then
        check_status "Smap version" "ok" "Version: $SMAP_VERSION"
    fi
fi

# Check Python modules
echo -e "\n${CYAN}🐍 Python Dependencies Check${NC}"
PYTHON_MODULES=("ipaddress" "json" "sys")
for module in "${PYTHON_MODULES[@]}"; do
    if python3 -c "import $module" 2>/dev/null; then
        check_status "Python $module" "ok"
    else
        check_status "Python $module" "error" "Required Python module missing"
    fi
done

# Check API configuration
echo -e "\n${CYAN}🔐 API Configuration Check${NC}"
API_COUNT=0

if [ -n "${GITHUB_TOKEN:-}" ]; then
    # Test GitHub API
    if curl -s -H "Authorization: token $GITHUB_TOKEN" "https://api.github.com/user" | grep -q "login"; then
        check_status "GitHub API" "ok" "Token valid and working"
        API_COUNT=$((API_COUNT + 1))
    else
        check_status "GitHub API" "warning" "Token configured but may be invalid"
    fi
else
    check_status "GitHub API" "warning" "Not configured (optional)"
fi

if [ -n "${CHAOS_API_KEY:-}" ]; then
    check_status "Chaos API" "ok" "Key configured"
    API_COUNT=$((API_COUNT + 1))
else
    check_status "Chaos API" "warning" "Not configured (optional)"
fi

if [ -n "${URLSCAN_API_KEY:-}" ]; then
    check_status "URLScan API" "ok" "Key configured"
    API_COUNT=$((API_COUNT + 1))
else
    check_status "URLScan API" "warning" "Not configured (optional)"
fi

if [ -n "${VIRUSTOTAL_API_KEY:-}" ]; then
    # Test VirusTotal API
    if curl -s -H "x-apikey: ${VIRUSTOTAL_API_KEY}" "https://www.virustotal.com/api/v3/domains/google.com" | grep -q "data"; then
        check_status "VirusTotal API" "ok" "Key valid and working"
        API_COUNT=$((API_COUNT + 1))
    else
        check_status "VirusTotal API" "warning" "Key configured but may be invalid"
    fi
else
    check_status "VirusTotal API" "warning" "Not configured (optional)"
fi

# Check configuration files
echo -e "\n${CYAN}⚙️  Configuration Files Check${NC}"
CONFIG_FILES=(
    "$INSTALL_DIR/config/environment_setup.sh"
    "$INSTALL_DIR/config/subfinder_config.yaml"
    "$INSTALL_DIR/setup_apis.sh"
    "$INSTALL_DIR/check_compatibility.sh"
)

for file in "${CONFIG_FILES[@]}"; do
    if [ -f "$file" ]; then
        if [ -x "$file" ]; then
            check_status "$(basename "$file")" "ok"
        else
            check_status "$(basename "$file")" "warning" "Not executable - fixing..."
            chmod +x "$file"
        fi
    else
        check_status "$(basename "$file")" "warning" "Configuration file missing"
    fi
done

# Check wordlists
echo -e "\n${CYAN}📚 Wordlists Check${NC}"
WORDLIST_FILES=(
    "$INSTALL_DIR/wordlists/enhanced_subdomains.txt"
    "$INSTALL_DIR/wordlists/subdomains-top1million-5000.txt"
    "$INSTALL_DIR/wordlists/config_endpoints.txt"
)

for file in "${WORDLIST_FILES[@]}"; do
    if [ -f "$file" ]; then
        LINES=$(wc -l < "$file" 2>/dev/null || echo "0")
        check_status "$(basename "$file")" "ok" "$LINES entries"
    else
        check_status "$(basename "$file")" "warning" "Wordlist missing"
    fi
done

# Check cloud ranges
echo -e "\n${CYAN}☁️  Cloud Ranges Check${NC}"
CLOUD_FILES=(
    "$INSTALL_DIR/cloud_ranges/aws_ec2_ranges.txt"
    "$INSTALL_DIR/cloud_ranges/gcp_ranges.txt"
    "$INSTALL_DIR/cloud_ranges/cloudflare_v4.txt"
    "$INSTALL_DIR/cloud_ranges/azure_ranges.txt"
)

CLOUD_RANGES_EXIST=0
for file in "${CLOUD_FILES[@]}"; do
    if [ -f "$file" ] && [ -s "$file" ]; then
        RANGES=$(wc -l < "$file" 2>/dev/null || echo "0")
        check_status "$(basename "$file")" "ok" "$RANGES ranges"
        CLOUD_RANGES_EXIST=$((CLOUD_RANGES_EXIST + 1))
    else
        check_status "$(basename "$file")" "warning" "Cloud ranges missing"
    fi
done

# Enhanced System Summary
echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                 ENHANCED SYSTEM SUMMARY v2.0                 ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"

# Determine system status
SYSTEM_READY=true
SYSTEM_MODE="UNKNOWN"

if [ ${#MISSING_ESSENTIAL[@]} -gt 0 ]; then
    SYSTEM_READY=false
    echo -e "${RED}❌ SYSTEM NOT READY: Missing essential tools${NC}"
    echo -e "   Install: ${MISSING_ESSENTIAL[*]}"
elif [ $API_COUNT -gt 0 ]; then
    SYSTEM_MODE="FULL"
    echo -e "${GREEN}✅ FULL MODE: $API_COUNT API(s) configured${NC}"
    echo -e "   Enhanced reconnaissance capabilities available"
else
    SYSTEM_MODE="BASIC"
    echo -e "${GREEN}✅ BASIC MODE: Professional reconnaissance ready${NC}"
    echo -e "   Using public sources and built-in capabilities"
fi

# Enhanced capability reporting
echo ""
echo -e "${CYAN}Enhanced Tool Status:${NC}"
echo -e "  Essential: $((${#ESSENTIAL_TOOLS[@]} - ${#MISSING_ESSENTIAL[@]}))/${#ESSENTIAL_TOOLS[@]} available"
echo -e "  Go Tools: $AVAILABLE_GO_TOOLS/${#GO_TOOLS[@]} available"
if [ "$SMAP_AVAILABLE" = true ]; then
    echo -e "  ${GREEN}Smap Integration: ACTIVE (passive scanning enabled)${NC}"
else
    echo -e "  ${YELLOW}Smap Integration: MISSING (install for 200x speed boost)${NC}"
fi
echo -e "  APIs: $API_COUNT/4 configured"
echo -e "  Cloud Ranges: $CLOUD_RANGES_EXIST/4 available"

# Recommendations with Smap focus
echo -e "\n${YELLOW}RECOMMENDATIONS:${NC}"

if [ ${#MISSING_ESSENTIAL[@]} -gt 0 ]; then
    echo -e "${RED}CRITICAL:${NC} Install missing essential tools:"
    for tool in "${MISSING_ESSENTIAL[@]}"; do
        echo -e "  • $tool"
    done
    echo ""
fi

if [ "$SMAP_AVAILABLE" = false ]; then
    echo -e "${YELLOW}HIGH PRIORITY:${NC} Install Smap for enhanced passive scanning:"
    echo -e "  ${CYAN}go install github.com/s0md3v/smap/cmd/smap@latest${NC}"
    echo -e "  Benefits:"
    echo -e "    • 200 hosts/second scanning speed"
    echo -e "    • No direct contact with targets (stealth)"
    echo -e "    • Vulnerability detection via Shodan data"
    echo -e "    • ~4000 ports scanned by default"
    echo ""
fi

if [ $AVAILABLE_GO_TOOLS -lt 4 ]; then
    echo -e "${YELLOW}ENHANCEMENT:${NC} Install additional Go tools for complete capabilities:"
    for tool in "${MISSING_GO_TOOLS[@]}"; do
        if [ "$tool" != "smap" ]; then  # Already covered above
            echo -e "  go install github.com/projectdiscovery/$tool/cmd/$tool@latest"
        fi
    done
    echo ""
fi

if [ $API_COUNT -eq 0 ]; then
    echo -e "${YELLOW}ENHANCEMENT:${NC} Configure free APIs for Full Mode:"
    echo -e "  Run: $INSTALL_DIR/setup_apis.sh"
    echo ""
fi

# Quick fixes
echo -e "${BLUE}QUICK FIXES:${NC}"
if [ ! -f "$INSTALL_DIR/ante.sh" ]; then
    echo -e "${RED}  ⚠ Main script missing - please copy ante.sh to $INSTALL_DIR/${NC}"
fi

if [ ${#MISSING_ESSENTIAL[@]} -eq 0 ] && [ "$SYSTEM_READY" = true ]; then
    echo -e "${GREEN}  ✅ System ready for enhanced reconnaissance!${NC}"
    echo ""
    echo -e "${CYAN}Test the system:${NC}"
    if [ "$SYSTEM_MODE" = "FULL" ]; then
        echo -e "  $INSTALL_DIR/ante.sh example.com"
    else
        echo -e "  $INSTALL_DIR/ante.sh example.com --no-apis"
    fi
    
    if [ "$SMAP_AVAILABLE" = true ]; then
        echo -e "\n${GREEN}Smap passive scanning ready:${NC}"
        echo -e "  • Ultra-fast reconnaissance without target contact"
        echo -e "  • Automatic vulnerability intelligence"
        echo -e "  • Perfect for large-scale assessments"
    fi
fi

# PATH check
echo -e "\n${CYAN}🛤️  PATH Configuration${NC}"
if echo "$PATH" | grep -q "$INSTALL_DIR"; then
    check_status "Ante in PATH" "ok"
    echo -e "   Available commands: ante, ante-check, ante-setup, ante-update-ranges"
else
    check_status "Ante in PATH" "warning" "Add to PATH for convenience"
    echo -e "   Run: echo 'export PATH=\"\$PATH:$INSTALL_DIR\"' >> ~/.bashrc"
fi

# Performance expectations
echo -e "\n${CYAN}🚀 Performance Expectations:${NC}"
if [ "$SMAP_AVAILABLE" = true ]; then
    echo -e "  ${GREEN}With Smap: ~200 hosts/second passive scanning${NC}"
    echo -e "  ${GREEN}Port discovery: ~4000 ports per target${NC}"
    echo -e "  ${GREEN}Stealth level: Maximum (no target contact)${NC}"
else
    echo -e "  ${YELLOW}Without Smap: Standard reconnaissance speed${NC}"
    echo -e "  ${YELLOW}Missing passive intelligence capabilities${NC}"
fi

echo -e "  Traditional scanning: 1000 ports per target"
echo -e "  Combined approach: Maximum coverage with speed"

echo -e "\n${GREEN}Enhanced compatibility check complete!${NC}"

# Exit with appropriate code
if [ "$SYSTEM_READY" = true ]; then
    exit 0
else
    exit 1
fi