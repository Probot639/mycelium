# PoC - two-stage build, needs real harness target copied in
FROM rust:1.82 AS build
WORKDIR /src
COPY . .
RUN cargo build --release --bin mycelium

FROM ubuntu:24.04
RUN apt-get update && apt-get install -y afl++ && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/mycelium /usr/local/bin/mycelium
# TODO: copy in the actual fuzzing target binary
ENTRYPOINT ["mycelium"]
