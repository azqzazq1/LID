#!/bin/bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo ""
echo -e "${CYAN}[LID] Setting up demo environment${NC}"
echo ""

# 1. Create secret file
echo "[*] Creating /tmp/secret_test_file.txt"
echo "SECRET_DATA=this_is_protected_content_12345" > /tmp/secret_test_file.txt
chmod 644 /tmp/secret_test_file.txt

# 2. Create hard link
echo "[*] Creating hard link /tmp/.aa_bypass_link"
ln -f /tmp/secret_test_file.txt /tmp/.aa_bypass_link

INODE=$(stat -c %i /tmp/secret_test_file.txt)
echo "    Inode: $INODE (shared by both paths)"

# 3. Compile test_reader
echo "[*] Compiling test_reader"
gcc -Wall -o /tmp/test_reader "$PROJECT_DIR/tests/test_reader.c"

# 4. Create AppArmor profile
echo "[*] Installing AppArmor profile"
cat > /etc/apparmor.d/tmp.test_reader << 'PROFILE'
#include <tunables/global>

/tmp/test_reader {
  #include <abstractions/base>

  /tmp/test_reader mr,

  # Deny the specific protected file
  deny /tmp/secret_test_file.txt rw,

  # Allow everything else in /tmp
  /tmp/** r,

  /proc/** r,
  /dev/null rw,
  /dev/tty rw,
}
PROFILE

apparmor_parser -r /etc/apparmor.d/tmp.test_reader 2>/dev/null

# 5. Verify denial
echo "[*] Verifying AppArmor enforcement..."
echo ""
if /tmp/test_reader 2>&1 | grep -qi "denied\|Permission"; then
    echo -e "${GREEN}[+] Demo environment ready — AppArmor is blocking access${NC}"
else
    echo -e "${RED}[-] WARNING: AppArmor did not deny access. Check profile.${NC}"
fi
echo ""
