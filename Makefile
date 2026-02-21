.PHONY: up down run run-dev test test-int build lint fmt env-check

# Start infrastructure (Postgres, Vault, Redis)
up:
	docker-compose up -d

# Start only infrastructure dependencies (Postgres, Vault, Redis) for local development
infra:
	docker-compose up -d db vault redis

# Stop infrastructure
down:
	docker-compose down

# Run the application locally with development defaults
# Automatically starts infrastructure if not running and sets dev API key
run:
	@echo "Checking infrastructure..."
	@docker-compose ps | grep -q "Up" || (echo "Starting infrastructure..." && docker-compose up -d db vault redis)
	@echo "Waiting for services..."
	@sleep 2
	@echo "Starting Crypto Wallets Service..."
	APP__SERVER__API_KEY=dev-local-key-change-in-production \
	APP__DATABASE__URL=postgres://postgres:postgres@localhost:5432/crypto_wallets \
	APP__VAULT__ADDRESS=http://localhost:8200 \
	APP__VAULT__TOKEN=root \
	APP__VAULT__KEY_ID=wallet-master-key \
	APP__REDIS__URL=redis://localhost:6379 \
	APP__REDIS__ENABLED=true \
	APP__REDIS__TTL_SECS=3600 \
	ALLOW_UNAUTHENTICATED=false \
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

# Quick development run (assumes infrastructure is already running)
run-dev:
	@echo "Starting with development defaults..."
	APP__SERVER__API_KEY=dev-local-key-change-in-production \
	APP__DATABASE__URL=postgres://postgres:postgres@localhost:5432/crypto_wallets \
	APP__VAULT__ADDRESS=http://localhost:8200 \
	APP__VAULT__TOKEN=root \
	APP__VAULT__KEY_ID=wallet-master-key \
	APP__REDIS__URL=redis://localhost:6379 \
	APP__REDIS__ENABLED=true \
	APP__REDIS__TTL_SECS=3600 \
	ALLOW_UNAUTHENTICATED=false \
	cargo run

# Check if environment is ready
env-check:
	@echo "Checking environment..."
	@echo "Postgres: $$(docker-compose ps | grep db | grep -q "Up" && echo "✅ Running" || echo "❌ Not running")"
	@echo "Vault: $$(docker-compose ps | grep vault | grep -q "Up" && echo "✅ Running" || echo "❌ Not running")"
	@echo "Redis: $$(docker-compose ps | grep redis | grep -q "Up" && echo "✅ Running" || echo "❌ Not running")"
	@echo ""
	@echo "Default development credentials:"
	@echo "  API Key: dev-local-key-change-in-production"
	@echo "  Database: postgres://postgres:postgres@localhost:5432/crypto_wallets"
	@echo "  Vault: http://localhost:8200 (token: root)"
	@echo "  Redis: redis://localhost:6379"
