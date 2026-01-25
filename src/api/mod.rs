use axum::{
    routing::{get, post},
    extract::{Path, Query, State},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::db::DbClient;
use crate::core::{WalletManager, Network, Address};
use crate::vault::VaultClient;
use std::sync::Arc;

pub struct AppState {
    pub db: DbClient,
    pub vault: VaultClient,
    pub wallet_manager: WalletManager,
}

#[derive(Serialize, Deserialize)]
pub struct CreateWalletRequest {
    pub label: String,
    pub mnemonic_length: Option<usize>,
}

#[derive(Deserialize)]
pub struct AddressQuery {
    pub index: u32,
}

pub mod grpc {
    tonic::include_proto!("crypto_wallet.v1");
}

use tonic::{Request, Response, Status};
use grpc::wallet_service_server::WalletService;
use grpc::{CreateWalletRequest as GrpcCreateWalletRequest, WalletInfo, GetAddressRequest as GrpcGetAddressRequest, AddressResponse, SignRequest, SignResponse};

pub struct MyWalletService {
    pub state: Arc<AppState>,
}

#[tonic::async_trait]
impl WalletService for MyWalletService {
    async fn create_wallet(&self, request: Request<GrpcCreateWalletRequest>) -> Result<Response<WalletInfo>, Status> {
        let req = request.into_inner();
        let length = 12; // Default
        let mnemonic = WalletManager::generate_mnemonic(length)
            .map_err(|e| {
                tracing::error!("Failed to generate mnemonic: {}", e);
                Status::internal("Internal error")
            })?;
        
        let encrypted = self.state.vault.encrypt(mnemonic.as_bytes()).await
            .map_err(|e: crate::vault::VaultError| {
                tracing::error!("Vault encryption failed: {}", e);
                Status::internal("Internal error")
            })?;
        
        let wallet: crate::db::MasterWallet = self.state.db.create_wallet(&req.label, &encrypted).await
            .map_err(|e: sqlx::Error| {
                tracing::error!("Database error: {}", e);
                Status::internal("Internal error")
            })?;
        
        Ok(Response::new(WalletInfo {
            id: wallet.id.to_string(),
            label: wallet.label,
        }))
    }

    async fn get_address(&self, request: Request<GrpcGetAddressRequest>) -> Result<Response<AddressResponse>, Status> {
        let req = request.into_inner();
        let id = Uuid::parse_str(&req.wallet_id).map_err(|_| Status::invalid_argument("Invalid UUID"))?;
        
        let wallet = self.state.db.get_wallet_by_id(id).await
            .map_err(|e| {
                tracing::warn!("Wallet not found: {} - {}", id, e);
                Status::not_found("Wallet not found")
            })?;
        
        let network = match req.network.as_str() {
            "eth" => Network::Ethereum,
            "tron" => Network::Tron,
            "sol" => Network::Solana,
            "ton" => Network::Ton,
            _ => return Err(Status::invalid_argument("Unsupported network")),
        };

        let address: Address = self.state.wallet_manager.get_address(&wallet.encrypted_phrase, network, req.index).await
            .map_err(|e: anyhow::Error| {
                tracing::error!("Derivation failed: {}", e);
                Status::internal("Internal error")
            })?;
        
        self.state.db.save_address(id, &req.network, req.index as i32, &address.to_string()).await
            .map_err(|e: sqlx::Error| {
                tracing::error!("Database error saving address: {}", e);
                Status::internal("Internal error")
            })?;

        Ok(Response::new(AddressResponse {
            address: address.to_string(),
            network: req.network,
        }))
    }

    async fn sign_transaction(&self, request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        let req = request.into_inner();
        let id = Uuid::parse_str(&req.wallet_id).map_err(|_| Status::invalid_argument("Invalid UUID"))?;
        
        let wallet = self.state.db.get_wallet_by_id(id).await
            .map_err(|e| {
                tracing::warn!("Wallet not found: {} - {}", id, e);
                Status::not_found("Wallet not found")
            })?;
        
        let network = match req.network.as_str() {
            "eth" => Network::Ethereum,
            "tron" => Network::Tron,
            "sol" => Network::Solana,
            "ton" => Network::Ton,
            _ => return Err(Status::invalid_argument("Unsupported network")),
        };

        let signed_tx: String = self.state.wallet_manager.sign_tx(&wallet.encrypted_phrase, network, req.index, &req.unsigned_tx).await
            .map_err(|e: anyhow::Error| {
                tracing::error!("Signing failed: {}", e);
                Status::internal("Internal error")
            })?;
        
        Ok(Response::new(SignResponse {
            signed_tx,
        }))
    }
}

async fn sign_transaction(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(payload): Json<SignTxRequest>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let wallet = state.db.get_wallet_by_id(id).await
        .map_err(|e: sqlx::Error| {
            tracing::warn!("Wallet not found: {} - {}", id, e);
            (axum::http::StatusCode::NOT_FOUND, "Wallet not found".to_string())
        })?;
    
    let network = match payload.network.as_str() {
        "eth" => Network::Ethereum,
        "tron" => Network::Tron,
        "sol" => Network::Solana,
        "ton" => Network::Ton,
        _ => return Err((axum::http::StatusCode::BAD_REQUEST, "Unsupported network".to_string())),
    };

    let signed_tx: String = state.wallet_manager.sign_tx(&wallet.encrypted_phrase, network, payload.index, &payload.unsigned_tx).await
        .map_err(|e: anyhow::Error| {
            tracing::error!("Signing failed: {}", e);
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string())
        })?;
    
    Ok(Json(serde_json::json!({
        "signed_tx": signed_tx
    })))
}

#[derive(Deserialize)]
pub struct SignTxRequest {
    pub network: String,
    pub index: u32,
    pub unsigned_tx: String,
}

pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/v1/wallets", post(create_wallet).get(list_wallets))
        .route("/api/v1/wallets/:id/address/:network", get(get_address))
        .route("/api/v1/wallets/:id/sign", post(sign_transaction))
        .route("/api/v1/health", get(health_check))
        .with_state(state)
}

async fn health_check() -> &'static str {
    "OK"
}

async fn create_wallet(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateWalletRequest>,
) -> Result<Json<crate::db::MasterWallet>, (axum::http::StatusCode, String)> {
    let length = payload.mnemonic_length.unwrap_or(12);
    if length != 12 && length != 24 {
        return Err((axum::http::StatusCode::BAD_REQUEST, "Mnemonic length must be 12 or 24".to_string()));
    }
    
    let mnemonic = WalletManager::generate_mnemonic(length)
        .map_err(|e: anyhow::Error| {
            tracing::error!("Failed to generate mnemonic: {}", e);
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string())
        })?;
    
    let encrypted: String = state.vault.encrypt(mnemonic.as_bytes()).await
        .map_err(|e: crate::vault::VaultError| {
            tracing::error!("Vault encryption failed: {}", e);
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string())
        })?;
    
    let wallet: crate::db::MasterWallet = state.db.create_wallet(&payload.label, &encrypted).await
        .map_err(|e: sqlx::Error| {
            tracing::error!("Database error: {}", e);
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string())
        })?;
    
    Ok(Json(wallet))
}

async fn list_wallets(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<crate::db::MasterWallet>>, (axum::http::StatusCode, String)> {
    let wallets: Vec<crate::db::MasterWallet> = state.db.get_wallets().await
        .map_err(|e: sqlx::Error| {
            tracing::error!("Database error: {}", e);
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string())
        })?;
    Ok(Json(wallets))
}

async fn get_address(
    State(state): State<Arc<AppState>>,
    Path((id, network_str)): Path<(Uuid, String)>,
    Query(query): Query<AddressQuery>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let wallet = state.db.get_wallet_by_id(id).await
        .map_err(|e: sqlx::Error| {
            tracing::warn!("Wallet not found: {} - {}", id, e);
            (axum::http::StatusCode::NOT_FOUND, "Wallet not found".to_string())
        })?;
    
    let network = match network_str.as_str() {
        "eth" => Network::Ethereum,
        "tron" => Network::Tron,
        "sol" => Network::Solana,
        "ton" => Network::Ton,
        _ => return Err((axum::http::StatusCode::BAD_REQUEST, "Unsupported network".to_string())),
    };

    let address: Address = state.wallet_manager.get_address(&wallet.encrypted_phrase, network, query.index).await
        .map_err(|e: anyhow::Error| {
            tracing::error!("Derivation failed: {}", e);
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string())
        })?;
    
    // Save address to DB
    state.db.save_address(id, &network_str, query.index as i32, &address.to_string()).await
        .map_err(|e: sqlx::Error| {
            tracing::error!("Database error saving address: {}", e);
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string())
        })?;

    Ok(Json(serde_json::json!({
        "wallet_id": id,
        "network": network_str,
        "index": query.index,
        "address": address.to_string()
    })))
}
