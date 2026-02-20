# Development
FROM rust:latest as dev
WORKDIR /app
RUN cargo install cargo-watch --version 8.5.2 --locked
COPY . .
CMD ["cargo-watch", "-x", "run"]

# Production
FROM rust:slim as builder
WORKDIR /app
# Install protobuf compiler for tonic
RUN apt-get update && apt-get install -y protobuf-compiler libssl-dev pkg-config
COPY . .
# Set SQLX_OFFLINE to true to skip DB check during build if needed, 
# or ensure sqlx-data.json is present.
RUN cargo build --release

FROM gcr.io/distroless/cc-debian12 as prod
WORKDIR /app
COPY --from=builder /app/target/release/crypto-wallets-service .
# Note: Do NOT copy config/default.toml - it contains development credentials.
# Production configuration must be provided via environment variables
# (APP__SERVER__PORT, APP__DATABASE__URL, APP__VAULT__TOKEN, etc.)
# Use a non-root user for security
USER 1000:1000
CMD ["./crypto-wallets-service"]
