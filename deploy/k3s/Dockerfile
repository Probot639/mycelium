# Build context is the repo root, not deploy/k3s:
#   docker build -f deploy/k3s/Dockerfile -t mycelium:dev .
#
# No fuzz target is baked in. Distributed-mode nodes download the harness from
# the coordinator at join time, so one image serves every campaign.

FROM rust:1.82-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --bin mycelium

FROM ubuntu:24.04
# afl++ pulls in afl-fuzz and the compiler wrappers. ca-certificates so the
# node can reach an https coordinator; plain http needs nothing extra.
RUN apt-get update \
    && apt-get install -y --no-install-recommends afl++ ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/mycelium /usr/local/bin/mycelium
# AFL++ writes a perf warning and bails if the host governor is throttled. In a
# container you usually cannot change the governor, so skip that check.
ENV AFL_SKIP_CPUFREQ=1
ENTRYPOINT ["mycelium"]
