.PHONY: up down run test test-int build lint fmt

# Start infrastructure (Postgres, Vault)
up:
	docker-compose up -d

# Start only infrastructure dependencies (Postgres, Vault) for local development
infra:
	docker-compose up -d db vault

# Stop infrastructure
down:
	docker-compose down

# Run the application
run:
	cargo run

# Run unit tests
test:
	cargo test --lib

# Run integration tests
test-int:
	cargo test --test integration_test

# Build production docker image
build:
	docker build -f docker/prod.Dockerfile -t crypto-wallets-service:latest .

# Check code style
lint:
	cargo clippy -- -D warnings

# Format code
fmt:
	cargo fmt
