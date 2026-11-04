#!/usr/bin/env bash
# Common build step, run on every guest after its packages are in.
# Builds mycelium from a writable per-guest copy of the repo, builds the AFL++
# harness natively (so its glibc matches this VM), and lays out the fuzz dirs.
set -euxo pipefail

# The 2GB boxes can OOM while linking the release build, so give them swap.
if ! swapon --show=NAME --noheadings | grep -q '/swapfile'; then
  fallocate -l 2G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=2048
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
fi

# Rust toolchain via rustup. mycelium is edition 2024, which the distro rustc
# on Jammy is far too old for, so rustup is the uniform choice on both distros.
export RUSTUP_HOME=/opt/rust/rustup
export CARGO_HOME=/opt/rust/cargo
if [ ! -x "$CARGO_HOME/bin/cargo" ]; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --no-modify-path --profile minimal
fi
export PATH="$CARGO_HOME/bin:$PATH"

# Build mycelium from a writable copy (the synced /vagrant is rsync, but keep
# the build tree per-guest and out of the shared mount).
rm -rf /opt/mycelium
mkdir -p /opt/mycelium
cp -a /vagrant/. /opt/mycelium/
cd /opt/mycelium
CARGO_BUILD_JOBS=2 cargo build --release --bin mycelium
install -m 0755 target/release/mycelium /usr/local/bin/mycelium
mycelium --help >/dev/null

# Build the AFL++ harness natively. afl-clang-fast is preferred; fall back
# through the other AFL++ compiler front ends if a box lacks it.
AFL_CC=""
for c in afl-clang-fast afl-clang-lto afl-cc afl-gcc-fast; do
  if command -v "$c" >/dev/null 2>&1; then AFL_CC="$c"; break; fi
done
[ -n "$AFL_CC" ] || { echo "no AFL++ compiler found on PATH"; exit 1; }
echo "building harness with $AFL_CC"
mkdir -p /opt/fuzz
"$AFL_CC" -O2 /vagrant/deploy/vagrant/harness/harness.c -o /opt/fuzz/harness

# Seeds and working dirs for the fuzzer.
mkdir -p /opt/fuzz/seeds /opt/fuzz/inject /opt/fuzz/out
printf 'hello' > /opt/fuzz/seeds/seed1
printf 'test'  > /opt/fuzz/seeds/seed2

# Coordinator data dir and the distributed-node workdir.
mkdir -p /opt/data /opt/data/corpus /opt/work

echo "build.sh done on $(hostname)"
