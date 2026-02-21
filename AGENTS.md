# Crypto Wallets Service - Agent Guide

## Project Overview

This is a high-performance, secure microservice for generating, storing, and signing cryptocurrency transactions. It is built with Rust using the Axum web framework and provides both HTTP REST and gRPC APIs.

### Key Capabilities

- **Multi-Chain Support**: Ethereum (ETH), Tron (TRX), Solana (SOL), TON
- **HD Wallet Generation**: BIP-32/39/44 hierarchical deterministic wallets
- **Secure Key Management**: Mnemonics encrypted via HashiCorp Vault Transit Engine
- **Transaction Signing**: Sign transactions without exposing private keys

### Architecture Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Client Requests                          │
│              (HTTP REST / gRPC / Swagger UI)                │
└───────────────────────┬─────────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────────┐
│                    API Layer (Axum/Tonic)                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ Auth Middleware│ │ Rate Limiting│ │  Swagger/OpenAPI    │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└───────────────────────┬─────────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────────┐
│                   Core Business Logic                       │
│         (WalletManager - mnemonic derivation)               │
└───────────────────────┬─────────────────────────────────────┘
                        │
        ┌───────────────┴───────────────┐
        │                               │
┌───────▼────────┐            ┌─────────▼──────────┐
│   PostgreSQL   │            │   HashiCorp Vault  │
│  (wallet data) │            │ (encryption keys)  │
└────────────────┘            └────────────────────┘
```

## Technology Stack

| Component | Technology | Version |
|-----------|------------|---------|
| Language | Rust | 2024 Edition (1.80+) |
| Web Framework | Axum | 0.7 |
| gRPC | Tonic | 0.12 |
| Async Runtime | Tokio | 1.x |
| Database | PostgreSQL | 15+ |
| ORM/Migrations | SQLx | 0.8 |
| Encryption | HashiCorp Vault | 1.21+ |
| Crypto Libraries | alloy, coins-bip32/39, ed25519-dalek, tonlib-core | various |
| API Documentation | Utoipa (OpenAPI/Swagger) | 4.x |
| Metrics | Prometheus (axum-prometheus) | 0.6 |
| Testing | testcontainers | 0.26 |

## Project Structure

```
crypto-wallets-service/
├── Cargo.toml              # Rust dependencies and metadata
├── Cargo.lock              # Locked dependency versions
├── build.rs                # Build script (protobuf compilation)
├── Makefile                # Common development tasks
├── docker-compose.yml      # Local development infrastructure
├── .gitlab-ci.yml          # CI/CD pipeline configuration
│
├── src/
│   ├── main.rs             # Application entry point
│   ├── lib.rs              # Library exports
│   ├── config.rs           # Configuration management (env vars + TOML)
│   ├── auth.rs             # Authentication utilities (IP extraction, etc.)
│   ├── api/
│   │   └── mod.rs          # HTTP/gRPC handlers, routing, middleware
│   ├── core/
│   │   └── mod.rs          # WalletManager, Network enum, crypto logic
│   ├── db/
│   │   └── mod.rs          # Database client, models (MasterWallet, etc.)
│   └── vault/
│       └── mod.rs          # Vault client (encrypt/decrypt with retry)
│
├── proto/
│   └── wallet.proto        # gRPC service definitions
│
├── migrations/
│   ├── 20240125000000_initial.sql          # Initial schema
│   ├── 20260125000001_create_audit_logs.sql # Audit logging
│   └── 20260221000000_add_indexes.sql       # Performance indexes
│
├── docker/
│   ├── prod.Dockerfile     # Production container build
│   └── vault-init.sh       # Vault initialization script
│
├── config/
│   └── default.toml        # Default configuration (development)
│
├── tests/
│   └── integration_test.rs # Integration tests with testcontainers
│
└── postman_collection.json # Postman API collection
```

## Build and Test Commands

### Prerequisites

- Rust 1.80+ with `cargo`
- Docker & Docker Compose
- Protocol Buffers compiler (`protoc`):
  ```bash
  # macOS
  brew install protobuf
  
  # Debian/Ubuntu
  apt install protobuf-compiler
  ```

### Development Commands (via Makefile)

| Command | Description |
|---------|-------------|
| `make up` | Start infrastructure (Postgres, Vault) |
| `make down` | Stop infrastructure |
| `make run` | Start infrastructure if needed and run the service with dev defaults |
| `make run-dev` | Run with dev defaults (assumes infrastructure running) |
| `make test` | Run unit tests (`cargo test --lib`) |
| `make test-int` | Run integration tests (requires Docker) |
| `make lint` | Run clippy with warnings as errors |
| `make fmt` | Format code with rustfmt |
| `make build` | Build production Docker image |
| `make env-check` | Check if infrastructure is running |

### Manual Cargo Commands

```bash
# Build
cargo build --release

# Run unit tests
cargo test --lib

# Run specific module tests
cargo test --lib core

# Run integration tests (requires Docker)
cargo test --test integration_test

# Check compilation
cargo check

# Linting
cargo clippy -- -D warnings

# Formatting
cargo fmt
```

## Configuration

Configuration uses a layered approach:
1. Default values from `config/default.toml`
2. Environment variables (prefix: `APP__`, separator: `__`)

### Required Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `APP__SERVER__API_KEY` | API key for authentication | `super-secret-key` |
| `APP__DATABASE__URL` | PostgreSQL connection string | `postgres://user:pass@localhost:5432/wallets` |
| `APP__VAULT__ADDRESS` | Vault server URL | `http://localhost:8200` |
| `APP__VAULT__TOKEN` | Vault authentication token | `root` |

### Optional Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `APP__SERVER__PORT` | `3000` | HTTP server port |
| `APP__SERVER__GRPC_PORT` | `port + 1` | gRPC server port |
| `APP__DATABASE__POOL_SIZE` | `20` | Max DB connections |
| `APP__DATABASE__MIN_CONNECTIONS` | `5` | Min DB connections |
| `APP__DATABASE__MAX_LIFETIME_SECS` | `600` | Connection max lifetime |
| `APP__DATABASE__IDLE_TIMEOUT_SECS` | `300` | Connection idle timeout |
| `APP__DATABASE__ACQUIRE_TIMEOUT_SECS` | `5` | Connection acquire timeout |
| `ALLOW_UNAUTHENTICATED` | `false` | Set to `true` to disable auth (dev only!) |
| `RUST_LOG` | `info` | Log level filter |

### Development Setup Example

```bash
# Start infrastructure
make up

# Run with defaults (sets dev credentials automatically)
make run

# Or manually with custom settings
export APP__SERVER__API_KEY=my-dev-key
export APP__DATABASE__URL="postgres://postgres:postgres@localhost:5432/crypto_wallets"
export APP__VAULT__ADDRESS="http://localhost:8200"
export APP__VAULT__TOKEN="root"
cargo run
```

## API Endpoints

### HTTP REST API

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/v1/health` | No | Health check (DB + Vault status) |
| GET | `/swagger-ui` | No | Swagger UI documentation |
| GET | `/metrics` | No | Prometheus metrics |
| POST | `/api/v1/wallets` | Yes | Create new wallet |
| GET | `/api/v1/wallets` | Yes | List wallets (paginated) |
| GET | `/api/v1/wallets/{id}/address/{network}` | Yes | Get derived address |
| POST | `/api/v1/wallets/{id}/sign` | Yes | Sign transaction |

### gRPC Services

Defined in `proto/wallet.proto`:
- `CreateWallet` - Create a new wallet
- `GetAddress` - Get derived address for a network
- `SignTransaction` - Sign a transaction

### Authentication

All protected endpoints require the `X-Api-Key` header:
```
X-Api-Key: your-secret-key-here
```

The service uses constant-time comparison to prevent timing attacks.

## Code Organization

### Module Responsibilities

| Module | File | Responsibility |
|--------|------|----------------|
| `api` | `src/api/mod.rs` | HTTP/gRPC route handlers, middleware, request/response types |
| `auth` | `src/auth.rs` | IP extraction with trusted proxy support, security utilities |
| `config` | `src/config.rs` | Configuration structs, environment parsing, defaults |
| `core` | `src/core/mod.rs` | WalletManager, Network enum, address derivation, transaction signing |
| `db` | `src/db/mod.rs` | SQLx queries, database models (MasterWallet, DerivedAddress) |
| `vault` | `src/vault/mod.rs` | Vault client with retry logic, encrypt/decrypt operations |

### Key Types and Traits

```rust
// src/core/mod.rs
pub enum Network {
    Ethereum,
    Tron,
    Solana,
    Ton,
}

pub struct WalletManager {
    vault: VaultClient,
}

impl WalletManager {
    pub fn generate_mnemonic(length: usize) -> anyhow::Result<String>;
    pub async fn get_address(&self, encrypted_seed: &str, network: Network, index: u32) -> anyhow::Result<Address>;
    pub async fn sign_tx(&self, encrypted_seed: &str, network: Network, index: u32, unsigned_tx: &str) -> anyhow::Result<String>;
}

// src/db/mod.rs
pub struct MasterWallet {
    pub id: Uuid,
    pub label: String,
    pub encrypted_phrase: String,  // Never serialized to API
    pub created_at: DateTime<Utc>,
}

pub struct DbClient {
    pool: Pool<Postgres>,
}

// src/vault/mod.rs
pub struct VaultClient {
    address: String,
    token: String,
    key_id: String,
    client: reqwest::Client,
}

impl VaultClient {
    pub async fn encrypt(&self, data: &[u8]) -> Result<String, VaultError>;
    pub async fn decrypt(&self, ciphertext: &str) -> Result<Vec<u8>, VaultError>;
}
```

## Testing Strategy

### Unit Tests

Located in-module (e.g., `src/core/mod.rs` has `#[cfg(test)]` module):
```bash
cargo test --lib
```

Key unit tests:
- Mnemonic generation (12 and 24 words)
- Derivation paths for each network
- Address derivation and format validation
- EIP-55 checksum verification
- IP extraction from headers

### Integration Tests

Located in `tests/integration_test.rs`, uses testcontainers:
```bash
make test-int
# or
cargo test --test integration_test
```

Integration test flow:
1. Starts PostgreSQL container
2. Starts Vault container with transit engine
3. Runs database migrations
4. Tests full API workflow:
   - Health check
   - Unauthorized request rejection
   - Wallet creation
   - Address derivation

### Adding a New Network

1. **Update Enum**: Add variant to `Network` in `src/core/mod.rs`
2. **Derivation Path**: Implement `Network::derivation_path()`
3. **Address Format**: Add case in `WalletManager::derive_address_from_mnemonic()`
4. **Signing Logic**: Add case in `WalletManager::sign_tx()`
5. **Validation**: Update `validate_transaction_format()`
6. **API Support**: Update network string mapping in `src/api/mod.rs`

## Security Considerations

### Critical Security Features

1. **API Key Authentication**: Mandatory in production (`APP__SERVER__API_KEY`)
2. **Constant-Time Comparison**: API keys compared using `subtle::ConstantTimeEq`
3. **Secret Redaction**: All config Debug implementations show `[REDACTED]` for secrets
4. **Encrypted Mnemonics**: Plaintext never stored; only Vault-encrypted ciphertext
5. **Audit Logging**: All sensitive operations logged with IP and details
6. **Trusted Proxy Support**: IP extraction prevents spoofing attacks

### Security Checklist for Changes

- [ ] Never log plaintext mnemonics or private keys
- [ ] Use `[REDACTED]` in Debug implementations for sensitive fields
- [ ] Use `zeroize` for sensitive byte arrays
- [ ] Validate all user inputs (UUIDs, network strings, hex data)
- [ ] Add audit logging for sensitive operations
- [ ] Use parameterized queries (SQLx does this automatically)
- [ ] Test authentication bypass scenarios

### Development vs Production

| Aspect | Development | Production |
|--------|-------------|------------|
| Auth | `ALLOW_UNAUTHENTICATED=true` possible | Must set `APP__SERVER__API_KEY` |
| Vault | Dev mode with root token | Production Vault with proper policies |
| Database | Local Docker container | Managed PostgreSQL with TLS |
| Logs | Pretty-printed | Structured JSON |
| Rate Limiting | May be disabled | Should be enabled |

## Database Schema

### Tables

**master_wallets**: Stores wallet metadata with encrypted mnemonics
```sql
id UUID PRIMARY KEY
label TEXT NOT NULL
encrypted_phrase TEXT NOT NULL  -- Vault-encrypted mnemonic
created_at TIMESTAMPTZ DEFAULT NOW()
```

**derived_addresses**: Cached derived addresses
```sql
id UUID PRIMARY KEY
wallet_id UUID REFERENCES master_wallets(id) ON DELETE CASCADE
network TEXT NOT NULL
address_index INTEGER NOT NULL
address TEXT NOT NULL
created_at TIMESTAMPTZ DEFAULT NOW()
UNIQUE(wallet_id, network, address_index)
```

**audit_logs**: Security audit trail
```sql
id UUID PRIMARY KEY
action VARCHAR(50) NOT NULL
wallet_id UUID REFERENCES master_wallets(id) ON DELETE SET NULL
status VARCHAR(20) NOT NULL
ip_address VARCHAR(45)
details JSONB
created_at TIMESTAMPTZ DEFAULT NOW()
```

### Indexes

- `idx_derived_addresses_wallet_id` - Lookup addresses by wallet
- `idx_derived_addresses_address` - Resolve address to wallet
- `idx_derived_addresses_wallet_network_index` - Derivation queries
- `idx_audit_logs_wallet_id` - Wallet history queries
- `idx_audit_logs_created_at` - Time-range queries

## Deployment

### Docker Production Build

```bash
make build
# or manually
docker build -f docker/prod.Dockerfile -t crypto-wallets-service:latest .
```

The production image:
- Uses multi-stage build (builder → distroless)
- Does NOT include config files (all config via env vars)
- Runs as non-root user (UID 1000)

### Required Production Configuration

```bash
docker run -p 3000:3000 \
  -e APP__SERVER__API_KEY=your-secret-key \
  -e APP__DATABASE__URL=postgres://... \
  -e APP__VAULT__ADDRESS=https://vault.example.com \
  -e APP__VAULT__TOKEN=... \
  -e APP__VAULT__KEY_ID=wallet-master-key \
  crypto-wallets-service:latest
```

### GitLab CI/CD

Pipeline stages:
1. **lint**: rustfmt check, clippy
2. **test**: Unit tests (`cargo test --lib core`)
3. **build**: Docker image build

Required GitLab variables:
- `CI_REGISTRY_USER`
- `CI_REGISTRY_PASSWORD`
- `CI_REGISTRY`

Runners must have the `docker` tag.

## Troubleshooting

### Common Issues

**Build fails with protobuf error:**
```bash
# Install protoc
apt install protobuf-compiler  # Linux
brew install protobuf          # macOS
```

**Database connection errors:**
```bash
# Check infrastructure
make env-check

# Start if needed
make up
```

**Vault connection errors:**
```bash
# Check Vault status
curl http://localhost:8200/v1/sys/health

# Re-initialize
make down && make up
```

**Integration tests fail:**
- Ensure Docker is running
- Check that ports 5432 and 8200 are not already in use
- Try: `docker system prune -f` to clean up containers

## Useful Resources

- [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) - Hierarchical Deterministic Wallets
- [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) - Mnemonic code for generating deterministic keys
- [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) - Multi-Account Hierarchy for Deterministic Wallets
- [EIP-55](https://eips.ethereum.org/EIPS/eip-55) - Mixed-case checksum address encoding
- [Vault Transit Secrets Engine](https://developer.hashicorp.com/vault/docs/secrets/transit)
- [Axum Documentation](https://docs.rs/axum/latest/axum/)
- [SQLx Documentation](https://docs.rs/sqlx/latest/sqlx/)
