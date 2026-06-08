#!/bin/bash
# ═══════════════════════════════════════════════════════
# Spider Noir — Installation Script
# ═══════════════════════════════════════════════════════

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo ""
echo -e "${CYAN}🕷  Spider Noir — Installer${NC}"
echo "═══════════════════════════════════════════════════════"
echo ""

# ── Python dependencies ──────────────────────────────────
echo -e "${YELLOW}[1/4]${NC} Installing Python dependencies..."
pip install pyvis rich --break-system-packages -q 2>/dev/null || \
pip install pyvis rich -q 2>/dev/null
echo -e "  ${GREEN}✓${NC} pyvis, rich installed"

# ── katana ────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[2/4]${NC} Checking katana..."
if command -v katana &>/dev/null; then
    echo -e "  ${GREEN}✓${NC} katana found: $(which katana)"
else
    echo -e "  ${RED}✗${NC} katana not found"
    echo -e "  Install: ${CYAN}go install github.com/projectdiscovery/katana/cmd/katana@latest${NC}"
    echo -e "  Or: ${CYAN}apt install katana${NC}"
fi

# ── ffuf ──────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[3/4]${NC} Checking ffuf..."
if command -v ffuf &>/dev/null; then
    echo -e "  ${GREEN}✓${NC} ffuf found: $(which ffuf)"
else
    echo -e "  ${RED}✗${NC} ffuf not found"
    echo -e "  Install: ${CYAN}apt install ffuf${NC}"
    echo -e "  Or: ${CYAN}go install github.com/ffuf/ffuf/v2@latest${NC}"
fi

# ── subfinder (optional) ─────────────────────────────────
echo ""
echo -e "${YELLOW}[4/4]${NC} Checking subfinder (optional, for Bug Bounty)..."
if command -v subfinder &>/dev/null; then
    echo -e "  ${GREEN}✓${NC} subfinder found: $(which subfinder)"
else
    echo -e "  ${YELLOW}○${NC} subfinder not found (optional)"
    echo -e "  Install: ${CYAN}wget https://github.com/projectdiscovery/subfinder/releases/download/v2.14.0/subfinder_2.14.0_linux_amd64.zip${NC}"
    echo -e "           ${CYAN}unzip subfinder_2.14.0_linux_amd64.zip && sudo mv subfinder /usr/local/bin/${NC}"
fi

# ── Summary ──────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════"
echo -e "${GREEN}Installation complete.${NC}"
echo -e "Run: ${CYAN}python3 spider_noir.py${NC}"
echo ""
