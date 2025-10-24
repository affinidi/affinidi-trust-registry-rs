# syntax=docker/dockerfile:1.7

###############################
# Build stage
###############################
FROM --platform=$BUILDPLATFORM rust:1.90 AS builder

ARG TARGETPLATFORM

WORKDIR /app

# Pre-copy manifest files to leverage Docker layer caching
COPY Cargo.toml Cargo.lock ./
COPY app/Cargo.toml app/
COPY http-server/Cargo.toml http-server/
COPY didcomm-server/Cargo.toml didcomm-server/
COPY sample-data/data.csv sample-data/data.csv

# TODO: fetch deps first and only then copy code to optimize build time
COPY . .

# Produce the binary in a deterministic location that we can copy later
RUN set -eux; \
    mkdir -p /app/dist; \
    cargo build --release --bin http-server; \
    cp target/release/http-server /app/dist/http-server

###############################
# Runtime stage
###############################
FROM --platform=linux/arm64 debian:trixie-slim AS runtime

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/dist/http-server /usr/local/bin/http-server
COPY --from=builder /app/sample-data/data.csv /usr/local/bin/sample-data/data.csv

ENV LISTEN_ADDRESS=0.0.0.0:3232 \
    RUST_LOG=info

EXPOSE 3232
ENTRYPOINT ["/usr/local/bin/http-server"]
