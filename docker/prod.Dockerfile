# Development
FROM rust:1.80 as dev
WORKDIR /app
RUN cargo install cargo-watch
COPY . .
CMD ["cargo-watch", "-x", "run"]

# Production
FROM rust:1.80-slim as builder
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
COPY --from=builder /app/config/default.toml ./config/
# Use a non-root user for security
USER 1000:1000
CMD ["./crypto-wallets-service"]
