# Changelog

All notable changes to this project will be documented in this file.

## [1.0.8] - 2026-02-21

### Infrastructure
- Add Redis caching support with configurable TTL
  - Cache derived addresses with Redis (migrating from in-memory LRU)
  - Cache health check status
  - Connection pooling with ConnectionManager
  - Optional Redis (can be disabled via config)

### Kubernetes Ready
- Add liveness probe endpoint: `/api/v1/health/live`
- Add readiness probe endpoint: `/api/v1/health/ready`
- Extended health check with latency metrics for all components
- Service is ready only when all dependencies are healthy

## [1.0.7] - 2026-02-21

### Security
- Add input validation for wallet creation requests (label length 1-100 chars, mnemonic length 12 or 24)
- Add 1MB body size limit for protected routes
- Add security scanning to CI/CD pipeline with Trivy and cargo-audit
- Scan Docker images for vulnerabilities after build
- Generate SBOM artifacts in CycloneDX format

### Reliability
- Add circuit breaker pattern for Vault client to prevent cascading failures
- Circuit breaker states: Closed (normal), Open (failing), HalfOpen (recovery testing)
- Return 503 Service Unavailable when circuit is open
- Add circuit state to health check endpoint
- Improve error handling and tracing for address derivation

### Performance
- Add LRU caching for derived addresses (default cache size: 1000)
- Cache key includes encrypted seed hash, network, and index
- Thread-safe cache with RwLock for concurrent access
- Cache statistics and clear method for monitoring

### Observability
- Add business metrics for Prometheus:
  - `wallets_created_total` - counter for wallet creation
  - `sign_operations_total` - counter with network and status labels
  - `vault_operations_duration_seconds` - histogram for Vault operations
  - `address_cache_size` - gauge for current cache size
  - `address_cache_capacity` - gauge for cache capacity

### Infrastructure
- Improve graceful shutdown for HTTP and gRPC servers
- Use coordinated shutdown via watch channel
- Add 30-second timeout for server shutdown
- Better error handling for server panics and timeouts

### Testing
- Add comprehensive test coverage (42+ unit tests)
- Add circuit breaker state transition tests
- Add transaction validation tests for all networks
- Add API input validation tests
- Extend integration tests with multi-network support
- Add gRPC integration test suite
- Add transaction signing tests for all networks

## [0.3.0] - 2024-01-25

### Added
- Initial release with multi-chain support (Ethereum, Tron, Solana, TON)
- HD wallet generation with BIP-32/39/44
- Secure key management with HashiCorp Vault Transit Engine
- Transaction signing without exposing private keys
- HTTP REST and gRPC APIs
- Swagger UI documentation
- Prometheus metrics
- Rate limiting
- Audit logging
- IP extraction with trusted proxy support
