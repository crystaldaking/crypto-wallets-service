use serde::{Deserialize, Serialize};
use thiserror::Error;
use base64::{engine::general_purpose, Engine as _};
use std::time::Duration;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Vault request failed: {0}")]
    RequestError(#[from] reqwest::Error),
    #[error("Vault error: {0}")]
    ApiError(String),
}

#[derive(Clone)]
pub struct VaultClient {
    address: String,
    token: String,
    key_id: String,
    client: reqwest::Client,
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
        
        Self {
            address,
            token,
            key_id,
            client,
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
        self.with_retry(
            || async { self.encrypt_internal(data).await },
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
        self.with_retry(
            || async { self.decrypt_internal(ciphertext).await },
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
}

// Need base64 crate too, or use alloy's if it exports it. Let's add base64 to Cargo.toml.
