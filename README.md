# Crypto Wallets Service

A high-performance, secure microservice for generating, storing, and signing cryptocurrency transactions (Mainnet/Testnet). Built with Rust, Axum, PostgreSQL, and HashiCorp Vault.

## 🚀 Features

*   **Multi-Chain Support**: Ethereum (ETH), Tron (TRX), Solana (SOL), TON.
*   **Security First**:
    *   Mnemonics are encrypted using **Transit Engine** in HashiCorp Vault.
    *   No plaintext keys stored in the database.
*   **HD Wallets**: Hierarchical Deterministic wallet generation (BIP-32/39/44).
*   **Observability**:
    *   Prometheus Metrics (`/metrics`).
    *   Structured Logging with `X-Request-ID` tracing.
*   **Documentation**:
    *   Swagger UI (`/swagger-ui`).
    *   Postman Collection included.
*   **Reliability**:
    *   Rate Limiting (Governor).
    *   Audit Logs for sensitive actions.
    *   Comprehensive Integration Tests with Testcontainers.

## 🛠 Architecture

*   **API Layer**: Rust (Axum) - Handles HTTP/gRPC requests.
*   **Storage**: PostgreSQL - Stores encrypted wallet metadata and derivation paths.
*   **Key Management**: HashiCorp Vault - Handles encryption/decryption on-the-fly. Key material never leaves the secure memory of the signing service.

## 🏁 Getting Started

### Prerequisites

*   Rust 1.80+
*   Docker & Docker Compose

### Running Locally

1.  **Start Infrastructure**:
    ```bash
    make up
    ```
    This starts Postgres (5432) and a self-configuring Vault (8200). 
    *Note: Vault is automatically initialized with the transit engine and master key via `docker/vault-init.sh`.*

2.  **Run the Service**:
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

Configuration is handled via `config/default.toml` or Environment Variables.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `SERVER.HOST` | `127.0.0.1` | Bind address |
| `SERVER.PORT` | `3000` | Port to listen on |
| `DATABASE.URL` | `postgres://...` | DB Connection String |
| `VAULT.URL` | `http://127.0.0.1:8200` | Vault Address |
| `VAULT.TOKEN` | `root` | Vault Token |

## 📖 API Documentation

*   **Swagger UI**: Open `http://localhost:3000/swagger-ui` in your browser.
*   **Health Check**: `GET /api/v1/health`
*   **Create Wallet**: `POST /api/v1/wallets`
*   **Sign Transaction**: `POST /api/v1/wallets/{id}/sign`

## 👨‍💻 Developer Guide

### Adding a New Network

1.  **Update Enum**: Add the network to `src/core/mod.rs` (`enum Network`).
2.  **Derivation Logic**: Implement the derivation path in `src/core/wallet.rs` (`get_derivation_path`).
3.  **Address Formatting**: Implement address encoding in `src/core/address.rs`.
4.  **Signing Logic**: Add signing support in `sign_tx` function.

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
- `CI_REGISTRY_USER`: Your GitLab Container Registry username (usually provided by GitLab).
- `CI_REGISTRY_PASSWORD`: Your GitLab Container Registry password/token (usually provided by GitLab).
- `CI_REGISTRY`: The address of the registry (usually provided by GitLab).

**Note on Runners:**
The CI/CD pipeline is configured to use runners with the `docker` tag. Ensure your GitLab runners have this tag enabled.

To enable automatic pushing of images, uncomment the `docker login` and `docker push` lines in `.gitlab-ci.yml`.

### Docker

Build the production image:
```bash
docker build -f docker/prod.Dockerfile -t crypto-wallets-service:latest .
```

Run with env vars:
```bash
docker run -p 3000:3000 -e DATABASE_URL=... -e VAULT_URL=... crypto-wallets-service:latest
```

## 🔒 Security Notes

*   Ensure Vault is sealed and running in production mode for real deployments.
*   Rotate the `VAULT_TOKEN` regularly.
*   Use TLS for all connections (Database, Vault, HTTP).

## 📄 License

MIT
