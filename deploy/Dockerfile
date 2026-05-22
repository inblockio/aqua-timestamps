# syntax=docker/dockerfile:1.7
# Multi-stage build. The repo is expected to be available alongside the
# sister-repo path-deps. Build context root is one level above.

# -------------------- BUILDER --------------------
FROM rust:1.95-bookworm AS builder

ENV CARGO_TERM_COLOR=always \
    RUSTFLAGS="-C target-cpu=x86-64-v2" \
    CARGO_INCREMENTAL=0

# OpenSSL dev headers for the SDK's "web" feature (RFC 3161 ASN.1).
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        ca-certificates \
        clang \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY aqua-rs-sdk                ./aqua-rs-sdk
COPY aqua-auth                  ./aqua-auth
COPY aqua-evm-provider          ./aqua-evm-provider
COPY aqua-qualified-verification ./aqua-qualified-verification
COPY aqua-timestamps            ./aqua-timestamps

WORKDIR /src/aqua-timestamps
RUN cargo build --release --bin aqua-timestamp \
    && strip target/release/aqua-timestamp

# -------------------- RUNTIME --------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        wget \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --shell /sbin/nologin --no-create-home aqua \
    && mkdir -p /var/lib/aqua-timestamp /etc/aqua-timestamp \
    && chown -R aqua:aqua /var/lib/aqua-timestamp

COPY --from=builder /src/aqua-timestamps/target/release/aqua-timestamp /usr/local/bin/aqua-timestamp

USER aqua
EXPOSE 8080

ENV RUST_LOG=info

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["/usr/local/bin/aqua-timestamp"]
CMD ["--config", "/etc/aqua-timestamp/config.toml"]
