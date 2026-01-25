use crypto_wallets_service::api::{AppState, create_router};
use crypto_wallets_service::config::AppConfig;
use crypto_wallets_service::core::WalletManager;
use crypto_wallets_service::db::DbClient;
use crypto_wallets_service::vault::VaultClient;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
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

    // Connect to DB
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database.url)
        .await?;

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
    let grpc_addr = std::net::SocketAddr::from(([0, 0, 0, 0], config.server.port + 1));
    tracing::info!("gRPC Server listening on {}", grpc_addr);

    let grpc_server = tonic::transport::Server::builder()
        .add_service(
            crypto_wallets_service::api::grpc::wallet_service_server::WalletServiceServer::new(
                grpc_service,
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
