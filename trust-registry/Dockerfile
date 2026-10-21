# syntax=docker/dockerfile:1.7

###############################
# Build stage
###############################
FROM --platform=$BUILDPLATFORM rust:1.95 AS builder

ARG TARGETPLATFORM
# Cargo features to build in, space-separated. Empty builds the default
# service. A VTA-provisioned registry needs `vta` (which also adds the
# `trust-registry setup` command); add a secrets backend for its offline
# cache, e.g. --build-arg FEATURES="vta secrets-vault tsp".
ARG FEATURES=""

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    pkg-config \
    libdbus-1-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY trust-registry/Cargo.toml trust-registry/
COPY sample-data/data.csv sample-data/data.csv

COPY . .

RUN set -eux; \
    mkdir -p /app/dist; \
    cargo build --release -p trust-registry --bin trust-registry ${FEATURES:+--features "$FEATURES"}; \
    cp target/release/trust-registry /app/dist/trust-registry

###############################
# Runtime stage
###############################
FROM debian:trixie-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    ca-certificates \
    libdbus-1-3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/dist/trust-registry /usr/local/bin/trust-registry
COPY --from=builder /app/sample-data/data.csv /usr/local/bin/sample-data/data.csv

ENV RUST_LOG=info

EXPOSE 3232
ENTRYPOINT ["/usr/local/bin/trust-registry"]
