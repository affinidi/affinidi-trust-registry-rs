# syntax=docker/dockerfile:1.7

# Base images are pinned by digest so a rebuild uses the image that was
# reviewed. To move to a newer one, take the digest of the tag's index:
#   docker buildx imagetools inspect rust:1.95 | sed -n 's/^Digest: *//p'

###############################
# Build stage
###############################
FROM --platform=$BUILDPLATFORM rust:1.95@sha256:f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3 AS builder

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
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    ca-certificates \
    libdbus-1-3 \
    && rm -rf /var/lib/apt/lists/*

# The service runs as an unprivileged user. Its working directory, /app, is
# the one place it may write: relative data paths (the CSV and fjall stores,
# ./.trust-registry for capability state and the secret cache) resolve there.
# The binary stays root-owned and read-only to it.
RUN groupadd --system --gid 10001 trustregistry \
    && useradd --system --uid 10001 --gid trustregistry \
    --home-dir /app --no-create-home --shell /usr/sbin/nologin trustregistry \
    && install -d -o trustregistry -g trustregistry -m 0750 /app

WORKDIR /app
COPY --from=builder /app/dist/trust-registry /usr/local/bin/trust-registry
COPY --chmod=0755 trust-registry/docker/healthcheck.sh /usr/local/bin/trust-registry-healthcheck
COPY --from=builder --chown=trustregistry:trustregistry /app/sample-data/data.csv /app/sample-data/data.csv

ENV RUST_LOG=info

USER trustregistry:trustregistry

EXPOSE 3232
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["/usr/local/bin/trust-registry-healthcheck"]
ENTRYPOINT ["/usr/local/bin/trust-registry"]
