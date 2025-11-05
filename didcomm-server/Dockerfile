# syntax=docker/dockerfile:1.7

###############################
# Build stage
###############################
FROM --platform=$BUILDPLATFORM rust:1.90 AS builder

ARG TARGETPLATFORM

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    pkg-config \
    libdbus-1-dev \
 && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY app/Cargo.toml app/
COPY http-server/Cargo.toml http-server/
COPY didcomm-server/Cargo.toml didcomm-server/
COPY sample-data/data.csv sample-data/data.csv

COPY . .

RUN set -eux; \
    mkdir -p /app/dist; \
    cargo build --release --bin didcomm-server; \
    cp target/release/didcomm-server /app/dist/didcomm-server

###############################
# Runtime stage
###############################
FROM --platform=linux/arm64 debian:trixie-slim AS runtime

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    ca-certificates \
    libdbus-1-3 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/dist/didcomm-server /usr/local/bin/didcomm-server
COPY --from=builder /app/sample-data/data.csv /usr/local/bin/sample-data/data.csv

ENV LISTEN_ADDRESS=0.0.0.0:3131 \
    RUST_LOG=info

EXPOSE 3131
ENTRYPOINT ["/usr/local/bin/didcomm-server"]
