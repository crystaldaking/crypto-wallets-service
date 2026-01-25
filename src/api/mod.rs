use crate::config::AppConfig;
use crate::core::{Address, Network, WalletManager};
use crate::db::DbClient;
use crate::vault::VaultClient;
use axum::{
    Json, Router,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::Response as AxumResponse,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

pub struct AppState {
    pub db: DbClient,
    pub vault: VaultClient,
    pub wallet_manager: WalletManager,
    pub config: AppConfig, // Added config to state
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

use grpc::wallet_service_server::WalletService;
use grpc::{
    AddressResponse, CreateWalletRequest as GrpcCreateWalletRequest,
    GetAddressRequest as GrpcGetAddressRequest, SignRequest, SignResponse, WalletInfo,
};
use tonic::{Request as TonicRequest, Response as TonicResponse, Status};

pub struct MyWalletService {
    pub state: Arc<AppState>,
}

#[tonic::async_trait]
impl WalletService for MyWalletService {
    async fn create_wallet(
        &self,
        request: TonicRequest<GrpcCreateWalletRequest>,
    ) -> Result<TonicResponse<WalletInfo>, Status> {
        let req = request.into_inner();
        let length = 12; // Default
        let mnemonic = WalletManager::generate_mnemonic(length).map_err(|e| {
            tracing::error!("Failed to generate mnemonic: {}", e);
            Status::internal("Internal error")
        })?;

        let encrypted = self
            .state
            .vault
            .encrypt(mnemonic.as_bytes())
            .await
            .map_err(|e: crate::vault::VaultError| {
                tracing::error!("Vault encryption failed: {}", e);
                Status::internal("Internal error")
            })?;

        let wallet: crate::db::MasterWallet = self
            .state
            .db
            .create_wallet(&req.label, &encrypted)
            .await
            .map_err(|e: sqlx::Error| {
                tracing::error!("Database error: {}", e);
                Status::internal("Internal error")
            })?;

        Ok(TonicResponse::new(WalletInfo {
            id: wallet.id.to_string(),
            label: wallet.label,
        }))
    }

    async fn get_address(
        &self,
        request: TonicRequest<GrpcGetAddressRequest>,
    ) -> Result<TonicResponse<AddressResponse>, Status> {
        let req = request.into_inner();
        let id = Uuid::parse_str(&req.wallet_id)
            .map_err(|_| Status::invalid_argument("Invalid UUID"))?;

        let wallet = self.state.db.get_wallet_by_id(id).await.map_err(|e| {
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

        let address: Address = self
            .state
            .wallet_manager
            .get_address(&wallet.encrypted_phrase, network, req.index)
            .await
            .map_err(|e: anyhow::Error| {
                tracing::error!("Derivation failed: {}", e);
                Status::internal("Internal error")
            })?;

        self.state
            .db
            .save_address(id, &req.network, req.index as i32, &address.to_string())
            .await
            .map_err(|e: sqlx::Error| {
                tracing::error!("Database error saving address: {}", e);
                Status::internal("Internal error")
            })?;

        Ok(TonicResponse::new(AddressResponse {
            address: address.to_string(),
            network: req.network,
        }))
    }

    async fn sign_transaction(
        &self,
        request: TonicRequest<SignRequest>,
    ) -> Result<TonicResponse<SignResponse>, Status> {
        let req = request.into_inner();
        let id = Uuid::parse_str(&req.wallet_id)
            .map_err(|_| Status::invalid_argument("Invalid UUID"))?;

        let wallet = self.state.db.get_wallet_by_id(id).await.map_err(|e| {
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

        let signed_tx: String = self
            .state
            .wallet_manager
            .sign_tx(
                &wallet.encrypted_phrase,
                network,
                req.index,
                &req.unsigned_tx,
            )
            .await
            .map_err(|e: anyhow::Error| {
                tracing::error!("Signing failed: {}", e);
                Status::internal("Internal error")
            })?;

        Ok(TonicResponse::new(SignResponse { signed_tx }))
    }
}

async fn sign_transaction(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(payload): Json<SignTxRequest>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let wallet = state
        .db
        .get_wallet_by_id(id)
        .await
        .map_err(|e: sqlx::Error| {
            tracing::warn!("Wallet not found: {} - {}", id, e);
            (
                axum::http::StatusCode::NOT_FOUND,
                "Wallet not found".to_string(),
            )
        })?;

    let network = match payload.network.as_str() {
        "eth" => Network::Ethereum,
        "tron" => Network::Tron,
        "sol" => Network::Solana,
        "ton" => Network::Ton,
        _ => {
            return Err((
                axum::http::StatusCode::BAD_REQUEST,
                "Unsupported network".to_string(),
            ));
        }
    };

    let signed_tx: String = state
        .wallet_manager
        .sign_tx(
            &wallet.encrypted_phrase,
            network,
            payload.index,
            &payload.unsigned_tx,
        )
        .await
        .map_err(|e: anyhow::Error| {
            tracing::error!("Signing failed: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error".to_string(),
            )
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

use tower::ServiceBuilder;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;

pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/v1/wallets", post(create_wallet).get(list_wallets))
        .route("/api/v1/wallets/:id/address/:network", get(get_address))
        .route("/api/v1/wallets/:id/sign", post(sign_transaction))
        .route("/api/v1/health", get(health_check))
        .layer(
            ServiceBuilder::new()
                .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
                .layer(PropagateRequestIdLayer::x_request_id())
                .layer(TraceLayer::new_for_http())
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    auth_middleware,
                )),
        )
        .with_state(state)
}

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<AxumResponse, StatusCode> {
    if let Some(required_key) = &state.config.server.api_key {
        match headers.get("X-Api-Key") {
            Some(key) if key == required_key => Ok(next.run(request).await),
            _ => {
                tracing::warn!("Unauthorized access attempt");
                Err(StatusCode::UNAUTHORIZED)
            }
        }
    } else {
        // No key configured, allow access
        Ok(next.run(request).await)
    }
}

async fn health_check(State(state): State<Arc<AppState>>) -> (StatusCode, Json<serde_json::Value>) {
    let db_status = match state.db.get_wallets().await {
        Ok(_) => "ok",
        Err(_) => "error",
    };

    // Simple Vault check (attempt to encrypt a dummy value to verify transit engine is up)
    let vault_status = match state.vault.encrypt(b"health_check").await {
        Ok(_) => "ok",
        Err(_) => "error",
    };

    let status_code = if db_status == "ok" && vault_status == "ok" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status_code,
        Json(serde_json::json!({
            "status": if status_code == StatusCode::OK { "ok" } else { "error" },
            "components": {
                "database": db_status,
                "vault": vault_status,
            }
        })),
    )
}

async fn create_wallet(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateWalletRequest>,
) -> Result<Json<crate::db::MasterWallet>, (axum::http::StatusCode, String)> {
    let length = payload.mnemonic_length.unwrap_or(12);
    if length != 12 && length != 24 {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            "Mnemonic length must be 12 or 24".to_string(),
        ));
    }

    let mnemonic = WalletManager::generate_mnemonic(length).map_err(|e: anyhow::Error| {
        tracing::error!("Failed to generate mnemonic: {}", e);
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error".to_string(),
        )
    })?;

    let encrypted: String =
        state
            .vault
            .encrypt(mnemonic.as_bytes())
            .await
            .map_err(|e: crate::vault::VaultError| {
                tracing::error!("Vault encryption failed: {}", e);
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error".to_string(),
                )
            })?;

    let wallet: crate::db::MasterWallet = state
        .db
        .create_wallet(&payload.label, &encrypted)
        .await
        .map_err(|e: sqlx::Error| {
            tracing::error!("Database error: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error".to_string(),
            )
        })?;

    Ok(Json(wallet))
}

async fn list_wallets(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<crate::db::MasterWallet>>, (axum::http::StatusCode, String)> {
    let wallets: Vec<crate::db::MasterWallet> =
        state.db.get_wallets().await.map_err(|e: sqlx::Error| {
            tracing::error!("Database error: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error".to_string(),
            )
        })?;
    Ok(Json(wallets))
}

async fn get_address(
    State(state): State<Arc<AppState>>,
    Path((id, network_str)): Path<(Uuid, String)>,
    Query(query): Query<AddressQuery>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let wallet = state
        .db
        .get_wallet_by_id(id)
        .await
        .map_err(|e: sqlx::Error| {
            tracing::warn!("Wallet not found: {} - {}", id, e);
            (
                axum::http::StatusCode::NOT_FOUND,
                "Wallet not found".to_string(),
            )
        })?;

    let network = match network_str.as_str() {
        "eth" => Network::Ethereum,
        "tron" => Network::Tron,
        "sol" => Network::Solana,
        "ton" => Network::Ton,
        _ => {
            return Err((
                axum::http::StatusCode::BAD_REQUEST,
                "Unsupported network".to_string(),
            ));
        }
    };

    let address: Address = state
        .wallet_manager
        .get_address(&wallet.encrypted_phrase, network, query.index)
        .await
        .map_err(|e: anyhow::Error| {
            tracing::error!("Derivation failed: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error".to_string(),
            )
        })?;

    // Save address to DB
    state
        .db
        .save_address(id, &network_str, query.index as i32, &address.to_string())
        .await
        .map_err(|e: sqlx::Error| {
            tracing::error!("Database error saving address: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error".to_string(),
            )
        })?;

    Ok(Json(serde_json::json!({
        "wallet_id": id,
        "network": network_str,
        "index": query.index,
        "address": address.to_string()
    })))
}
