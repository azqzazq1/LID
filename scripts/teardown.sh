#!/bin/bash
set -euo pipefail

echo "[*] Tearing down LID demo environment..."

# Kill any running loaders
pkill -f lid_loader 2>/dev/null || true

# Remove test artifacts
rm -f /tmp/secret_test_file.txt /tmp/.aa_bypass_link /tmp/test_reader

# Remove AppArmor profile
if [ -f /etc/apparmor.d/tmp.test_reader ]; then
    apparmor_parser -R /etc/apparmor.d/tmp.test_reader 2>/dev/null || true
    rm -f /etc/apparmor.d/tmp.test_reader
fi
if [ -f /etc/apparmor.d/tmp.test_reader_link ]; then
    apparmor_parser -R /etc/apparmor.d/tmp.test_reader_link 2>/dev/null || true
    rm -f /etc/apparmor.d/tmp.test_reader_link
fi

echo "[+] Cleanup complete"
