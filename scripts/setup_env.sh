#!/bin/bash
set -euo pipefail

echo "[*] Installing LID build dependencies..."

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq clang llvm libbpf-dev gcc make \
    linux-tools-common linux-tools-"$(uname -r)" \
    apparmor apparmor-utils 2>/dev/null || true

cd "$(dirname "$0")/.."

if [ ! -f vmlinux.h ]; then
    echo "[*] Generating vmlinux.h from kernel BTF..."
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
    echo "[+] vmlinux.h generated ($(wc -l < vmlinux.h) lines)"
fi

echo "[+] Environment ready. Run: make"
