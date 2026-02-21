use serde::{Deserialize, Serialize};
use thiserror::Error;
use base64::{engine::general_purpose, Engine as _};
use std::time::{Duration, Instant};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Vault request failed: {0}")]
    RequestError(#[from] reqwest::Error),
    #[error("Vault error: {0}")]
    ApiError(String),
    #[error("Circuit breaker is open - Vault is temporarily unavailable")]
    CircuitOpen,
}

/// Circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq)]
enum CircuitState {
    /// Normal operation, requests pass through
    Closed,
    /// Failure threshold reached, requests are rejected
    Open,
    /// Testing if service has recovered
    HalfOpen,
}

/// Circuit breaker configuration
#[derive(Clone, Debug)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening the circuit
    pub failure_threshold: u32,
    /// Duration to wait before attempting recovery
    pub recovery_timeout_secs: u64,
    /// Number of successes required to close the circuit from half-open
    pub success_threshold: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            recovery_timeout_secs: 30,
            success_threshold: 3,
        }
    }
}

/// Circuit breaker for Vault operations
struct CircuitBreaker {
    state: CircuitState,
    failure_count: u32,
    success_count: u32,
    last_failure_time: Option<Instant>,
    config: CircuitBreakerConfig,
}

impl CircuitBreaker {
    fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            state: CircuitState::Closed,
            failure_count: 0,
            success_count: 0,
            last_failure_time: None,
            config,
        }
    }

    /// Check if request can proceed
    fn can_execute(&mut self) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if recovery timeout has passed
                if let Some(last_failure) = self.last_failure_time {
                    if last_failure.elapsed().as_secs() >= self.config.recovery_timeout_secs {
                        tracing::info!("Circuit breaker entering half-open state");
                        self.state = CircuitState::HalfOpen;
                        self.success_count = 0;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => true,
        }
    }

    /// Record a successful operation
    fn record_success(&mut self) {
        match self.state {
            CircuitState::Closed => {
                self.failure_count = 0;
            }
            CircuitState::HalfOpen => {
                self.success_count += 1;
                if self.success_count >= self.config.success_threshold {
                    tracing::info!("Circuit breaker closed - Vault recovered");
                    self.state = CircuitState::Closed;
                    self.failure_count = 0;
                    self.success_count = 0;
                }
            }
            CircuitState::Open => {
                // Should not happen, but handle gracefully
                self.state = CircuitState::HalfOpen;
                self.success_count = 1;
            }
        }
    }

    /// Record a failed operation
    fn record_failure(&mut self) {
        self.failure_count += 1;
        self.last_failure_time = Some(Instant::now());

        match self.state {
            CircuitState::Closed => {
                if self.failure_count >= self.config.failure_threshold {
                    tracing::warn!(
                        "Circuit breaker opened after {} consecutive failures",
                        self.failure_count
                    );
                    self.state = CircuitState::Open;
                }
            }
            CircuitState::HalfOpen => {
                tracing::warn!("Circuit breaker opened - recovery attempt failed");
                self.state = CircuitState::Open;
            }
            CircuitState::Open => {
                // Already open, just update the timestamp
            }
        }
    }

    /// Get current state for metrics/monitoring
    fn state(&self) -> CircuitState {
        self.state
    }
}

#[derive(Clone)]
pub struct VaultClient {
    address: String,
    token: String,
    key_id: String,
    client: reqwest::Client,
    circuit_breaker: Arc<RwLock<CircuitBreaker>>,
}

#[derive(Serialize)]
struct TransitEncryptRequest {
    plaintext: String,
}

#[derive(Deserialize)]
struct TransitData {
    ciphertext: String,
}

#[derive(Deserialize)]
struct VaultResponse<T> {
    data: T,
}

#[derive(Serialize)]
struct TransitDecryptRequest {
    ciphertext: String,
}

#[derive(Deserialize)]
struct TransitDecryptedData {
    plaintext: String,
}

/// Configuration for retry behavior
#[derive(Clone, Debug)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay_ms: 100,
            max_delay_ms: 5000,
        }
    }
}

impl VaultClient {
    pub fn new(address: String, token: String, key_id: String) -> Self {
        // Build client with timeouts to prevent hanging on network issues
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))        // Total request timeout
            .connect_timeout(Duration::from_secs(5)) // Connection timeout
            .build()
            .expect("Failed to build reqwest client");
        
        let circuit_breaker = Arc::new(RwLock::new(CircuitBreaker::new(
            CircuitBreakerConfig::default()
        )));
        
        Self {
            address,
            token,
            key_id,
            client,
            circuit_breaker,
        }
    }

    /// Execute an operation with circuit breaker protection
    async fn with_circuit_breaker<T, F, Fut>(
        &self,
        operation: F,
        operation_name: &str,
    ) -> Result<T, VaultError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T, VaultError>>,
    {
        // Check circuit breaker
        {
            let mut cb = self.circuit_breaker.write().await;
            if !cb.can_execute() {
                tracing::warn!("{} rejected - circuit breaker is open", operation_name);
                return Err(VaultError::CircuitOpen);
            }
        }

        // Execute operation
        match operation().await {
            Ok(result) => {
                let mut cb = self.circuit_breaker.write().await;
                cb.record_success();
                Ok(result)
            }
            Err(e) => {
                // Only record failures for network/server errors, not client errors
                let should_record_failure = matches!(&e,
                    VaultError::RequestError(req_err) if req_err.is_timeout() 
                        || req_err.is_connect()
                        || req_err.status().map(|s| s.is_server_error()).unwrap_or(false)
                );

                if should_record_failure {
                    let mut cb = self.circuit_breaker.write().await;
                    cb.record_failure();
                }
                Err(e)
            }
        }
    }

    /// Execute an operation with exponential backoff retry logic
    async fn with_retry<T, F, Fut>(
        &self,
        operation: F,
        operation_name: &str,
    ) -> Result<T, VaultError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T, VaultError>>,
    {
        let config = RetryConfig::default();
        let mut last_error = None;

        for attempt in 0..=config.max_retries {
            match operation().await {
                Ok(result) => {
                    if attempt > 0 {
                        tracing::info!("{} succeeded after {} retries", operation_name, attempt);
                    }
                    return Ok(result);
                }
                Err(e) => {
                    // Don't retry if circuit breaker is open
                    if matches!(e, VaultError::CircuitOpen) {
                        return Err(e);
                    }

                    let should_retry = matches!(&e, 
                        VaultError::RequestError(req_err) if req_err.is_timeout() 
                            || req_err.is_connect()
                            || req_err.status().map(|s| s.is_server_error()).unwrap_or(false)
                    );

                    if !should_retry || attempt == config.max_retries {
                        return Err(e);
                    }

                    last_error = Some(e);
                    let delay_ms = std::cmp::min(
                        config.base_delay_ms * 2_u64.pow(attempt),
                        config.max_delay_ms,
                    );
                    tracing::warn!(
                        "{} failed (attempt {}/{}), retrying in {}ms: {:?}",
                        operation_name,
                        attempt + 1,
                        config.max_retries + 1,
                        delay_ms,
                        last_error
                    );
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
            }
        }

        Err(last_error.unwrap_or_else(|| VaultError::ApiError("Max retries exceeded".to_string())))
    }

    pub async fn encrypt(&self, data: &[u8]) -> Result<String, VaultError> {
        self.with_circuit_breaker(
            || async {
                self.with_retry(
                    || async { self.encrypt_internal(data).await },
                    "Vault encrypt",
                ).await
            },
            "Vault encrypt",
        ).await
    }

    async fn encrypt_internal(&self, data: &[u8]) -> Result<String, VaultError> {
        tracing::debug!("Encrypting data with Vault");
        let url = format!("{}/v1/transit/encrypt/{}", self.address, self.key_id);
        // Vault Transit expects base64-encoded plaintext directly
        let plaintext = general_purpose::STANDARD.encode(data);
        
        let resp = self.client.post(&url)
            .header("X-Vault-Token", &self.token)
            .json(&TransitEncryptRequest { plaintext })
            .send()
            .await?;

        if !resp.status().is_success() {
            let err_text = resp.text().await?;
            tracing::error!("Vault encryption failed: {}", err_text);
            return Err(VaultError::ApiError(err_text));
        }

        let body: VaultResponse<TransitData> = resp.json().await?;
        Ok(body.data.ciphertext)
    }

    pub async fn decrypt(&self, ciphertext: &str) -> Result<Vec<u8>, VaultError> {
        self.with_circuit_breaker(
            || async {
                self.with_retry(
                    || async { self.decrypt_internal(ciphertext).await },
                    "Vault decrypt",
                ).await
            },
            "Vault decrypt",
        ).await
    }

    async fn decrypt_internal(&self, ciphertext: &str) -> Result<Vec<u8>, VaultError> {
        tracing::debug!("Decrypting data with Vault");
        let url = format!("{}/v1/transit/decrypt/{}", self.address, self.key_id);
        
        let resp = self.client.post(&url)
            .header("X-Vault-Token", &self.token)
            .json(&TransitDecryptRequest { ciphertext: ciphertext.to_string() })
            .send()
            .await?;

        if !resp.status().is_success() {
            let err_text = resp.text().await?;
            tracing::error!("Vault decryption failed: {}", err_text);
            return Err(VaultError::ApiError(err_text));
        }

        let body: VaultResponse<TransitDecryptedData> = resp.json().await?;
        // Vault returns base64-encoded plaintext directly
        let bytes = general_purpose::STANDARD.decode(body.data.plaintext).map_err(|e| {
            tracing::error!("Base64 decode failed: {}", e);
            VaultError::ApiError(e.to_string())
        })?;
        Ok(bytes)
    }

    /// Get current circuit breaker state for health checks
    pub async fn circuit_state(&self) -> &'static str {
        let cb = self.circuit_breaker.read().await;
        match cb.state() {
            CircuitState::Closed => "closed",
            CircuitState::Open => "open",
            CircuitState::HalfOpen => "half_open",
        }
    }
}
