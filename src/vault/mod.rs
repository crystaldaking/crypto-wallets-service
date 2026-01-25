use serde::{Deserialize, Serialize};
use thiserror::Error;
use base64::{engine::general_purpose, Engine as _};

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

impl VaultClient {
    pub fn new(address: String, token: String, key_id: String) -> Self {
        Self {
            address,
            token,
            key_id,
            client: reqwest::Client::new(),
        }
    }

    pub async fn encrypt(&self, data: &[u8]) -> Result<String, VaultError> {
        tracing::debug!("Encrypting data with Vault");
        let url = format!("{}/v1/transit/encrypt/{}", self.address, self.key_id);
        let plaintext = hex::encode(data);
        
        let resp = self.client.post(&url)
            .header("X-Vault-Token", &self.token)
            .json(&TransitEncryptRequest { plaintext: general_purpose::STANDARD.encode(plaintext) })
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
        let decoded = general_purpose::STANDARD.decode(body.data.plaintext).map_err(|e| {
            tracing::error!("Base64 decode failed: {}", e);
            VaultError::ApiError(e.to_string())
        })?;
        let hex_data = String::from_utf8(decoded).map_err(|e| {
            tracing::error!("UTF-8 decode failed: {}", e);
            VaultError::ApiError(e.to_string())
        })?;
        let bytes = hex::decode(hex_data).map_err(|e| {
            tracing::error!("Hex decode failed: {}", e);
            VaultError::ApiError(e.to_string())
        })?;
        Ok(bytes)
    }
}

// Need base64 crate too, or use alloy's if it exports it. Let's add base64 to Cargo.toml.
