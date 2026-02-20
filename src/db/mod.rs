use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use std::fmt;
use uuid::Uuid;

use utoipa::ToSchema;

#[derive(Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct MasterWallet {
    pub id: Uuid,
    pub label: String,
    /// Encrypted mnemonic phrase - never serialized to API responses
    #[serde(skip_serializing)]
    pub encrypted_phrase: String,
    pub created_at: DateTime<Utc>,
}

impl fmt::Debug for MasterWallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasterWallet")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("encrypted_phrase", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct DerivedAddress {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub network: String,
    pub address_index: i32,
    pub address: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct DbClient {
    pool: Pool<Postgres>,
}

impl DbClient {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }

    pub async fn create_wallet(
        &self,
        label: &str,
        encrypted_phrase: &str,
    ) -> Result<MasterWallet, sqlx::Error> {
        sqlx::query_as::<_, MasterWallet>(
            "INSERT INTO master_wallets (label, encrypted_phrase) VALUES ($1, $2) RETURNING *",
        )
        .bind(label)
        .bind(encrypted_phrase)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn get_wallets(&self) -> Result<Vec<MasterWallet>, sqlx::Error> {
        sqlx::query_as::<_, MasterWallet>("SELECT * FROM master_wallets")
            .fetch_all(&self.pool)
            .await
    }

    /// Get wallets with pagination
    pub async fn get_wallets_paginated(
        &self,
        page: i64,
        per_page: i64,
    ) -> Result<Vec<MasterWallet>, sqlx::Error> {
        let offset = (page - 1) * per_page;
        sqlx::query_as::<_, MasterWallet>(
            "SELECT * FROM master_wallets ORDER BY created_at DESC LIMIT $1 OFFSET $2"
        )
        .bind(per_page)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
    }

    /// Get total count of wallets
    pub async fn get_wallets_count(&self) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar("SELECT COUNT(*) FROM master_wallets")
            .fetch_one(&self.pool)
            .await
    }

    /// Lightweight health check query
    pub async fn health_check(&self) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT 1").fetch_one(&self.pool).await.map(|_| ())
    }

    pub async fn get_wallet_by_id(&self, id: Uuid) -> Result<MasterWallet, sqlx::Error> {
        sqlx::query_as::<_, MasterWallet>("SELECT * FROM master_wallets WHERE id = $1")
            .bind(id)
            .fetch_one(&self.pool)
            .await
    }

    pub async fn save_address(
        &self,
        wallet_id: Uuid,
        network: &str,
        index: i32,
        address: &str,
    ) -> Result<DerivedAddress, sqlx::Error> {
        sqlx::query_as::<_, DerivedAddress>(
            "INSERT INTO derived_addresses (wallet_id, network, address_index, address) 
             VALUES ($1, $2, $3, $4) 
             ON CONFLICT (wallet_id, network, address_index) DO UPDATE SET address = EXCLUDED.address
             RETURNING *"
        )
        .bind(wallet_id)
        .bind(network)
        .bind(index)
        .bind(address)
        .fetch_one(&self.pool)
        .await
    }
    pub async fn log_audit_event(
        &self,
        action: &str,
        wallet_id: Option<Uuid>,
        status: &str,
        ip_address: Option<String>,
        details: Option<serde_json::Value>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO audit_logs (action, wallet_id, status, ip_address, details) VALUES ($1, $2, $3, $4, $5)"
        )
        .bind(action)
        .bind(wallet_id)
        .bind(status)
        .bind(ip_address)
        .bind(details)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
