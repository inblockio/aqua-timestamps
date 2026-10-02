# syntax=docker/dockerfile:1.7
# Multi-stage build, run on the dev host by deploy/deploy.sh (the production box
# has 4 GB shared with the Matrix stack, too little for a release build). The
# build context is the repository root: the train dependencies are git pins in Cargo.toml, so there
# are no sibling checkouts. aqua-auth and the crates.io dependencies are fetched
# during the build; the private aqua-rs-sdk source arrives vendored in the
# context (`vendor/` + `.cargo/config.toml`, written by deploy.sh), so the build
# needs no GitHub credentials. Build it with `--format docker` under podman, or
# the HEALTHCHECK below is dropped.

# -------------------- BUILDER --------------------
FROM docker.io/library/rust:1.95-bookworm AS builder

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

# Stamped into the binary by crates/aqua-timestamp/build.rs (there is no .git in
# the context) and served at GET /version.
ARG GIT_SHA=unknown
ARG GIT_DIRTY=0

WORKDIR /src
COPY . .
RUN cargo build --release --locked --bin aqua-timestamp \
    && strip target/release/aqua-timestamp

# -------------------- RUNTIME --------------------
FROM docker.io/library/debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        wget \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --shell /sbin/nologin --no-create-home aqua \
    && mkdir -p /var/lib/aqua-timestamp /etc/aqua-timestamp \
    && chown -R aqua:aqua /var/lib/aqua-timestamp

COPY --from=builder /src/target/release/aqua-timestamp /usr/local/bin/aqua-timestamp

# Source revision of the image (also GET /version), so a deployed artifact can be
# traced to its commit without running it.
ARG GIT_SHA=unknown
LABEL org.opencontainers.image.revision=$GIT_SHA \
      org.opencontainers.image.source="https://github.com/inblockio/aqua-timestamps"

USER aqua
EXPOSE 8080

ENV RUST_LOG=info

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["/usr/local/bin/aqua-timestamp"]
CMD ["--config", "/etc/aqua-timestamp/config.toml"]
