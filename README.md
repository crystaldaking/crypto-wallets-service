# Crypto Wallets Service

A high-performance, secure microservice for generating, storing, and signing cryptocurrency transactions (Mainnet/Testnet). Built with Rust, Axum, PostgreSQL, and HashiCorp Vault.

## 🚀 Features

*   **Multi-Chain Support**: Ethereum (ETH), Tron (TRX), Solana (SOL), TON.
*   **Security First**:
    *   Mnemonics are encrypted using **Transit Engine** in HashiCorp Vault.
    *   No plaintext keys stored in the database.
    *   Constant-time API key comparison (timing attack protection).
    *   Mandatory API key authentication (with explicit opt-out for development).
    *   Secrets redacted from logs (`[REDACTED]`).
*   **HD Wallets**: Hierarchical Deterministic wallet generation (BIP-32/39/44).
*   **Observability**:
    *   Prometheus Metrics (`/metrics`).
    *   Structured Logging with `X-Request-ID` tracing.
    *   Audit Logs for all sensitive actions.
*   **Documentation**:
    *   Swagger UI (`/swagger-ui`).
    *   Postman Collection included.
*   **Reliability**:
    *   Rate Limiting (Governor).
    *   Pagination for large datasets.
    *   Comprehensive Integration Tests with Testcontainers.
    *   Database connection pooling with configurable size.

## 🛠 Architecture

*   **API Layer**: Rust (Axum) - Handles HTTP/gRPC requests.
*   **Storage**: PostgreSQL - Stores encrypted wallet metadata and derivation paths.
*   **Key Management**: HashiCorp Vault - Handles encryption/decryption on-the-fly. Key material never leaves the secure memory of the signing service.

## 🏁 Getting Started

### Prerequisites

*   Rust 1.80+
*   Docker & Docker Compose
*   Protocol Buffers compiler (`protoc`):
    ```bash
    # macOS
    brew install protobuf
    
    # Debian/Ubuntu
    apt install protobuf-compiler
    ```

### Running Locally

1.  **Start Infrastructure**:
    ```bash
    make up
    ```
    This starts Postgres (5432) and a self-configuring Vault (8200). 
    *Note: Vault is automatically initialized with the transit engine and master key via `docker/vault-init.sh`.*

2.  **Set API Key** (required for production):
    ```bash
    export APP__SERVER__API_KEY=your-secret-key-here
    ```
    Or for development only (NOT for production):
    ```bash
    export ALLOW_UNAUTHENTICATED=true
    ```

3.  **Run the Service**:
    ```bash
    make run
    ```
    The server listens on `0.0.0.0:3000` (HTTP) and `0.0.0.0:3001` (gRPC).

### Makefile Commands

| Command | Description |
| :--- | :--- |
| `make up` | Start infrastructure (Postgres, Vault) |
| `make down` | Stop infrastructure |
| `make test-int` | Run integration tests |
| `make lint` | Run clippy |
| `make fmt` | Format code |

## 📖 API Documentation

*   **Swagger UI**: Open `http://localhost:3000/swagger-ui` in your browser.
*   **gRPC Proto**: Definitions available in `proto/wallet.proto`.
*   **Postman**: Import `postman_collection.json` for manual testing.

## ⚙️ Configuration

Configuration is handled via Environment Variables (prefix: `APP__`, separator: `__`).

| Variable | Default | Description |
| :--- | :--- | :--- |
| `APP__SERVER__PORT` | `3000` | HTTP port to listen on |
| `APP__SERVER__GRPC_PORT` | `3001` | gRPC port (defaults to port + 1) |
| `APP__SERVER__API_KEY` | *required* | API key for authentication |
| `APP__DATABASE__URL` | — | PostgreSQL connection string |
| `APP__DATABASE__POOL_SIZE` | `20` | Database connection pool size |
| `APP__VAULT__ADDRESS` | `http://127.0.0.1:8200` | Vault Address |
| `APP__VAULT__TOKEN` | `root` | Vault Token |
| `APP__VAULT__KEY_ID` | `wallet-master-key` | Transit encryption key name |

### Example

```bash
export APP__SERVER__PORT=3000
export APP__SERVER__API_KEY=super-secret-key
export APP__DATABASE__URL="postgres://user:pass@localhost:5432/wallets"
export APP__DATABASE__POOL_SIZE=50
export APP__VAULT__ADDRESS="http://127.0.0.1:8200"
export APP__VAULT__TOKEN="root"
```

## 📝 API Endpoints

*   **Health Check**: `GET /api/v1/health`
*   **Create Wallet**: `POST /api/v1/wallets`
*   **List Wallets** (paginated): `GET /api/v1/wallets?page=1&per_page=20`
*   **Get Address**: `GET /api/v1/wallets/{id}/address/{network}?index=0`
*   **Sign Transaction**: `POST /api/v1/wallets/{id}/sign`

## 👨‍💻 Developer Guide

### Adding a New Network

1.  **Update Enum**: Add the network to `src/core/mod.rs` (`enum Network`).
2.  **Derivation Logic**: Implement the derivation path in `Network::derivation_path()`.
3.  **Address Formatting**: Implement address encoding in `WalletManager::derive_address_from_mnemonic()`.
4.  **Signing Logic**: Add signing support in `WalletManager::sign_tx()` function.

### Running Tests

*   **Unit Tests**:
    ```bash
    cargo test --lib
    ```
*   **Integration Tests**:
    Requires Docker. Spins up real containers.
    ```bash
    cargo test --test integration_test
    ```

## 📦 Deployment

### GitLab CI/CD

The project includes a `.gitlab-ci.yml` file for automated linting, testing, and building. 

**Required GitLab Variables:**
- `CI_REGISTRY_USER`: Your GitLab Container Registry username
- `CI_REGISTRY_PASSWORD`: Your GitLab Container Registry password/token
- `CI_REGISTRY`: The address of the registry

**Note on Runners:**
The CI/CD pipeline is configured to use runners with the `docker` tag. Ensure your GitLab runners have this tag enabled.

### Docker

Build the production image:
```bash
docker build -f docker/prod.Dockerfile -t crypto-wallets-service:latest .
```

**Important**: Production image does NOT contain development configuration. You MUST provide all configuration via environment variables:

```bash
docker run -p 3000:3000 \
  -e APP__SERVER__API_KEY=your-secret-key \
  -e APP__DATABASE__URL=postgres://... \
  -e APP__VAULT__ADDRESS=http://vault:8200 \
  -e APP__VAULT__TOKEN=... \
  crypto-wallets-service:latest
```

## 🔒 Security Notes

*   **API Key is mandatory** - Service will not start without `APP__SERVER__API_KEY` unless `ALLOW_UNAUTHENTICATED=true` is explicitly set (dev only).
*   Ensure Vault is sealed and running in production mode for real deployments.
*   Rotate the `VAULT_TOKEN` regularly.
*   Use TLS for all connections (Database, Vault, HTTP) in production.
*   All secrets are redacted from logs (`[REDACTED]`).

## 📄 License

MIT

---

**Version 1.0.5** - See [CHANGELOG.md](CHANGELOG.md) for release notes.
