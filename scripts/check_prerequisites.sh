#!/bin/bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; ERRORS=$((ERRORS+1)); }
warn() { echo -e "  ${YELLOW}!${NC} $1"; }

ERRORS=0

echo ""
echo "  ██╗     ██╗██████╗ "
echo "  ██║     ██║██╔══██╗"
echo "  ██║     ██║██║  ██║"
echo "  ██║     ██║██║  ██║"
echo "  ███████╗██║██████╔╝"
echo "  ╚══════╝╚═╝╚═════╝ "
echo "  Prerequisite Check"
echo ""

# Kernel version
KVER=$(uname -r)
KMAJOR=$(echo "$KVER" | cut -d. -f1)
if [ "$KMAJOR" -ge 5 ]; then
    pass "Kernel $KVER (>= 5.x required)"
else
    fail "Kernel $KVER too old (need >= 5.x)"
fi

# Root check
if [ "$(id -u)" -eq 0 ]; then
    pass "Running as root"
else
    fail "Not root — LID requires root or CAP_BPF+CAP_PERFMON"
fi

# Kernel configs
KCONFIG="/boot/config-$KVER"
if [ -f "$KCONFIG" ]; then
    for opt in CONFIG_BPF CONFIG_BPF_SYSCALL CONFIG_BPF_KPROBE_OVERRIDE CONFIG_DEBUG_INFO_BTF; do
        if grep -q "^${opt}=y" "$KCONFIG" 2>/dev/null; then
            pass "$opt=y"
        else
            fail "$opt not enabled"
        fi
    done
else
    warn "Kernel config not found at $KCONFIG — skipping config checks"
fi

# BTF availability
if [ -f /sys/kernel/btf/vmlinux ]; then
    pass "BTF available (/sys/kernel/btf/vmlinux)"
else
    fail "BTF not available — cannot generate vmlinux.h"
fi

# AppArmor
if [ -d /sys/kernel/security/apparmor ]; then
    pass "AppArmor loaded"
    AA_MODE=$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo "?")
    if [ "$AA_MODE" = "Y" ]; then
        pass "AppArmor enabled"
    else
        warn "AppArmor loaded but not enabled"
    fi
else
    fail "AppArmor not loaded"
fi

# Tools
for tool in clang gcc bpftool make apparmor_parser; do
    if command -v $tool &>/dev/null; then
        pass "$tool found ($(command -v $tool))"
    else
        fail "$tool not found — install with: apt install ${tool/apparmor_parser/apparmor-utils}"
    fi
done

# libbpf headers
if [ -f /usr/include/bpf/libbpf.h ]; then
    pass "libbpf-dev headers found"
else
    fail "libbpf-dev not installed — apt install libbpf-dev"
fi

# Linux headers
if [ -d "/usr/src/linux-headers-$KVER" ]; then
    pass "Linux headers for $KVER found"
else
    warn "Linux headers for $KVER not found (may not be needed)"
fi

echo ""
if [ $ERRORS -eq 0 ]; then
    echo -e "  ${GREEN}All checks passed. Ready to build LID.${NC}"
else
    echo -e "  ${RED}$ERRORS check(s) failed. Fix the above issues before building.${NC}"
fi
echo ""
