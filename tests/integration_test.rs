use axum::extract::ConnectInfo;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use crypto_wallets_service::{api, config, core, db, vault};
use reqwest;
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceExt; // for oneshot // Added for reqwest::Client
use tracing_subscriber;

#[tokio::test]
async fn full_integration_test() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    use testcontainers::{GenericImage, ImageExt, runners::AsyncRunner};
    use testcontainers_modules::postgres::Postgres;

    // 1. Start Containers

    // Postgres
    let pg_container = Postgres::default()
        .start()
        .await
        .expect("Failed to start postgres");
    let pg_port = pg_container
        .get_host_port_ipv4(5432)
        .await
        .expect("Failed to get PG port");
    let db_url = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        pg_port
    );

    // Vault
    // Create image and set properties. Order matters for types in earlier versions/wrappers.
    // GenericImage implements Image.
    let vault_image = GenericImage::new("hashicorp/vault", "latest")
        // .with_wait_for(WaitFor::message_on_stderr("Vault server started!")) // Rely on manual poll
        .with_env_var("VAULT_DEV_ROOT_TOKEN_ID", "root")
        .with_env_var("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:8200");

    let vault_container = vault_image.start().await.expect("Failed to start vault");
    let vault_port = vault_container
        .get_host_port_ipv4(8200)
        .await
        .expect("Failed to get Vault port");
    let vault_addr = format!("http://127.0.0.1:{}", vault_port);

    // 2. Setup Vault (Enable Transit & Create Key)
    let client = reqwest::Client::new();

    // Wait for Vault to be ready (Double check via API)
    let mut attempts = 0;
    loop {
        if attempts > 20 {
            panic!("Vault not ready");
        }
        if client
            .get(format!("{}/v1/sys/health", vault_addr))
            .send()
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        attempts += 1;
    }

    // Enable Transit
    client
        .post(format!("{}/v1/sys/mounts/transit", vault_addr))
        .header("X-Vault-Token", "root")
        .json(&serde_json::json!({ "type": "transit" }))
        .send()
        .await
        .expect("Failed to enable transit")
        .error_for_status()
        .unwrap();

    // Create Key
    client
        .post(format!("{}/v1/transit/keys/master-key", vault_addr))
        .header("X-Vault-Token", "root")
        .send()
        .await
        .expect("Failed to create key")
        .error_for_status()
        .unwrap();

    // 3. Setup Config
    let config = config::AppConfig {
        server: config::ServerConfig {
            port: 0,
            api_key: Some("test-secret-key".to_string()),
            rate_limit: config::RateLimitConfig {
                enabled: true,
                requests_per_second: 10,
                burst_size: 5,
            },
            trusted_proxies: vec![],
        },
        database: config::DatabaseConfig {
            url: db_url.clone(),
        },
        vault: config::VaultConfig {
            address: vault_addr.clone(),
            token: "root".to_string(),
            key_id: "master-key".to_string(),
        },
    };

    // 4. Setup DB & Migrations
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .expect("Failed to connect to DB");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    let db_client = db::DbClient::new(pool);
    let vault_client = vault::VaultClient::new(
        config.vault.address.clone(),
        config.vault.token.clone(),
        config.vault.key_id.clone(),
    );

    // 5. Setup App State
    let wallet_manager = core::WalletManager::new(vault_client.clone());
    let state = Arc::new(api::AppState {
        db: db_client,
        vault: vault_client,
        wallet_manager,
        config: config.clone(),
    });

    let app = api::create_router(state);

    // 6. Test Scenario

    // A. Health Check
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/health")
                .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1234))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["status"], "ok");

    // B. Create Wallet (unauthorized)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/wallets")
                .header("Content-Type", "application/json")
                .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1234))))
                .body(Body::from(r#"{"label": "test-wallet"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // C. Create Wallet (authorized)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/wallets")
                .header("Content-Type", "application/json")
                .header("X-Api-Key", "test-secret-key")
                .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1234))))
                .body(Body::from(r#"{"label": "test-wallet"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: Value = serde_json::from_slice(&body_bytes).unwrap();
    let wallet_id = body_json["id"].as_str().unwrap();
    assert_eq!(body_json["label"], "test-wallet");

    // D. Get Address (ETH)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/wallets/{}/address/eth?index=0", wallet_id))
                .header("X-Api-Key", "test-secret-key")
                .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1234))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: Value = serde_json::from_slice(&body_bytes).unwrap();
    let address = body_json["address"].as_str().unwrap();
    assert!(address.starts_with("0x"));

    println!("Integration test passed!");
}
