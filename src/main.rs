use crypto_wallets_service::api::{AppState, create_router};
use crypto_wallets_service::config::AppConfig;
use crypto_wallets_service::core::WalletManager;
use crypto_wallets_service::db::DbClient;
use crypto_wallets_service::vault::VaultClient;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    // Load config
    let config = AppConfig::build().expect("Failed to load configuration");

    // Require API key for production or explicit opt-out
    if config.server.api_key.is_none() {
        let allow_unauthenticated = std::env::var("ALLOW_UNAUTHENTICATED")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        
        if !allow_unauthenticated {
            tracing::error!("❌ API key is not configured!");
            tracing::error!("❌ Set APP__SERVER__API_KEY environment variable to start the service.");
            tracing::error!("❌ Or set ALLOW_UNAUTHENTICATED=true to explicitly allow unauthenticated access (NOT RECOMMENDED FOR PRODUCTION).");
            panic!("API key is required. Set APP__SERVER__API_KEY or ALLOW_UNAUTHENTICATED=true");
        }
        
        tracing::warn!("⚠️  SECURITY WARNING: Running without API key authentication!");
        tracing::warn!("⚠️  This is NOT recommended for production environments.");
    }

    // Connect to DB with configurable pool options
    let pool = PgPoolOptions::new()
        .max_connections(config.database.pool_size)
        .min_connections(config.database.min_connections)
        .max_lifetime(Duration::from_secs(config.database.max_lifetime_secs))
        .idle_timeout(Duration::from_secs(config.database.idle_timeout_secs))
        .acquire_timeout(Duration::from_secs(config.database.acquire_timeout_secs))
        .connect(&config.database.url)
        .await?;
    tracing::info!(
        "Database pool initialized: min={}, max={}, acquire_timeout={}s",
        config.database.min_connections,
        config.database.pool_size,
        config.database.acquire_timeout_secs
    );

    // Run migrations
    sqlx::migrate!("./migrations").run(&pool).await?;

    let db_client = DbClient::new(pool);
    let vault_client = VaultClient::new(
        config.vault.address.clone(),
        config.vault.token.clone(),
        config.vault.key_id.clone(),
    );
    let wallet_manager = WalletManager::new(vault_client.clone());

    let state = Arc::new(AppState {
        db: db_client,
        vault: vault_client,
        wallet_manager,
        config: config.clone(),
    });

    // Build router
    let app = create_router(state.clone());

    // gRPC server
    let grpc_service = crypto_wallets_service::api::MyWalletService {
        state: state.clone(),
    };
    let grpc_addr = std::net::SocketAddr::from(([0, 0, 0, 0], config.server.grpc_port()));
    tracing::info!("gRPC Server listening on {}", grpc_addr);

    // Create interceptor for auth and rate limiting
    let auth_interceptor = crypto_wallets_service::api::check_auth_interceptor(
        state.config.server.api_key.clone(),
    );
    
    // Combine auth and rate limiting
    let rate_limit_config = if config.server.rate_limit.enabled {
        Some(config.server.rate_limit.clone())
    } else {
        None
    };
    let grpc_interceptor = crypto_wallets_service::api::combined_interceptor(
        auth_interceptor,
        rate_limit_config,
    );

    let grpc_server = tonic::transport::Server::builder()
        .add_service(
            crypto_wallets_service::api::grpc::wallet_service_server::WalletServiceServer::with_interceptor(
                grpc_service,
                grpc_interceptor,
            ),
        )
        .serve_with_shutdown(grpc_addr, shutdown_signal());

    // HTTP server
    let http_addr = std::net::SocketAddr::from(([0, 0, 0, 0], config.server.port));
    tracing::info!("HTTP Server listening on {}", http_addr);

    let listener = tokio::net::TcpListener::bind(http_addr).await?;
    let http_server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal());

    // Run both
    tokio::select! {
        res = http_server => res.map_err(anyhow::Error::from),
        res = grpc_server => res.map_err(anyhow::Error::from),
    }?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Shutdown signal received");
}
