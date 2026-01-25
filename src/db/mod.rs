use sqlx::{Pool, Postgres};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct MasterWallet {
    pub id: Uuid,
    pub label: String,
    pub encrypted_phrase: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
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

    pub async fn create_wallet(&self, label: &str, encrypted_phrase: &str) -> Result<MasterWallet, sqlx::Error> {
        sqlx::query_as::<_, MasterWallet>(
            "INSERT INTO master_wallets (label, encrypted_phrase) VALUES ($1, $2) RETURNING *"
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

    pub async fn get_wallet_by_id(&self, id: Uuid) -> Result<MasterWallet, sqlx::Error> {
        sqlx::query_as::<_, MasterWallet>("SELECT * FROM master_wallets WHERE id = $1")
            .bind(id)
            .fetch_one(&self.pool)
            .await
    }

    pub async fn save_address(&self, wallet_id: Uuid, network: &str, index: i32, address: &str) -> Result<DerivedAddress, sqlx::Error> {
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
}
