# RunTools Auth Service — Dockerfile
#
# Multi-stage build:
#   Stage 1 (builder): Compile Rust binary with all dependencies
#   Stage 2 (runtime): Minimal Debian slim image with just the binary
#
# Build args intentionally minimal — all config comes from environment at runtime.

# ── Stage 1: Build ─────────────────────────────────────────────────────────────
FROM rust:1-slim-bookworm AS builder

WORKDIR /app

# Install build dependencies for sqlx (openssl + pkg-config)
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Cache dependency build separately (invalidates only when Cargo.toml/lock changes)
COPY Cargo.toml Cargo.lock ./

# Dummy src to build deps layer — avoids recompiling all crates on code changes
RUN mkdir src && echo 'fn main() {}' > src/main.rs
RUN cargo build --release --bin runtools-auth
RUN rm -rf src

# Copy real source and build
COPY src ./src
# Touch to force Rust to relink
RUN touch src/main.rs
RUN cargo build --release --bin runtools-auth

# ── Stage 2: Runtime ───────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

WORKDIR /app

# ca-certificates: required for TLS connections to WorkOS API, JWKS endpoint, etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -g 1001 runtools && useradd -u 1001 -g runtools -s /bin/sh runtools

# Copy binary from builder
COPY --from=builder /app/target/release/runtools-auth /usr/local/bin/runtools-auth

# Switch to non-root
USER runtools

# Port (must match PORT env var — default 8420)
EXPOSE 8420

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8420/v1/status || exit 1

CMD ["/usr/local/bin/runtools-auth"]
