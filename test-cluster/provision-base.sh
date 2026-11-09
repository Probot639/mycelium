#!/bin/bash
# Common provisioning for Arch Linux VMs.
set -euo pipefail

# Pacman setup: initialize keyring if stale, update
pacman-key --init 2>/dev/null || true
pacman-key --populate archlinux 2>/dev/null || true
pacman -Sy --noconfirm archlinux-keyring 2>/dev/null || true
pacman -Syu --noconfirm

# Install build deps + AFL++
pacman -S --noconfirm --needed \
    base-devel clang llvm lld gcc make \
    python git cmake afl++ 2>/dev/null || true

# Install mycelium binary (host-built, same glibc)
cp /vagrant/mycelium /usr/local/bin/mycelium
chmod +x /usr/local/bin/mycelium
mycelium --help > /dev/null 2>&1 && echo "mycelium binary OK" || { echo "mycelium binary failed"; exit 1; }

# Kernel tuning for AFL++
echo core > /proc/sys/kernel/core_pattern 2>/dev/null || true
echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null || true
