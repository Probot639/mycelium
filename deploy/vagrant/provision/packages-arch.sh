#!/usr/bin/env bash
# Arch package install. The box image is a couple of years old, so refresh the
# keyring and do a full sync first: Arch is rolling and a plain -Sy would risk a
# partial-upgrade mismatch. The AFL++ package is "afl++" (extra); openssl and
# pkgconf cover mycelium's openssl-sys build dependency.
set -euxo pipefail

pacman -Sy --noconfirm --needed archlinux-keyring
pacman -Su --noconfirm
pacman -S --noconfirm --needed \
  base-devel clang llvm afl++ \
  curl ca-certificates git rsync \
  openssl pkgconf
