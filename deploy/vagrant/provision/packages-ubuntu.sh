#!/usr/bin/env bash
# Ubuntu package install. afl++ is the AFL++ package name on Jammy; pkg-config
# and libssl-dev are needed because mycelium's reqwest pulls in openssl-sys.
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y \
  build-essential clang llvm afl++ \
  curl ca-certificates git rsync \
  pkg-config libssl-dev
