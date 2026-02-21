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
use std::time::Duration;
use tokio::time::timeout;
use tower::ServiceExt; // for oneshot // Added for reqwest::Client
use tracing_subscriber;

// Import gRPC types
use api::grpc::{
    wallet_service_client::WalletServiceClient,
    CreateWalletRequest as GrpcCreateWalletRequest, GetAddressRequest as GrpcGetAddressRequest,
};

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
            grpc_port: None, // Will use port + 1
            api_key: Some("test-secret-key".to_string()),
            rate_limit: config::RateLimitConfig {
                enabled: false, // Disable rate limiting for tests
                requests_per_second: 100,
                burst_size: 100,
            },
            trusted_proxies: vec![],
        },
        database: config::DatabaseConfig {
            url: db_url.clone(),
            pool_size: 5, // Smaller pool for tests
            min_connections: 1,
            max_lifetime_secs: 60,
            idle_timeout_secs: 30,
            acquire_timeout_secs: 3,
        },
        vault: config::VaultConfig {
            address: vault_addr.clone(),
            token: "root".to_string(),
            key_id: "master-key".to_string(),
        },
        redis: config::RedisConfig {
            url: "redis://127.0.0.1:6379".to_string(),
            ttl_secs: 3600,
            enabled: false, // Disable Redis for integration tests
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

    // E. Get Tron Address
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/wallets/{}/address/tron?index=0",
                    wallet_id
                ))
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
    let tron_address = body_json["address"].as_str().unwrap();
    assert!(tron_address.starts_with("T"));

    // F. Get Solana Address
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/wallets/{}/address/sol?index=0",
                    wallet_id
                ))
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
    let solana_address = body_json["address"].as_str().unwrap();
    // Solana addresses are base58 encoded and typically 32-44 characters
    assert!(solana_address.len() >= 32 && solana_address.len() <= 44);

    // G. Get TON Address
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/wallets/{}/address/ton?index=0",
                    wallet_id
                ))
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
    let ton_address = body_json["address"].as_str().unwrap();
    // TON bounceable addresses start with "EQ"
    assert!(ton_address.starts_with("EQ"));

    // H. Test pagination (add small delay to avoid rate limit)
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/wallets?page=1&per_page=10")
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
    assert!(body_json["data"].is_array());
    assert_eq!(body_json["page"], 1);
    assert_eq!(body_json["per_page"], 10);

    // I. Test invalid pagination (should return 400)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/wallets?page=0&per_page=10") // page < 1
                .header("X-Api-Key", "test-secret-key")
                .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1234))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // J. Test per_page too high (should return 400)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/wallets?page=1&per_page=200") // per_page > 100
                .header("X-Api-Key", "test-secret-key")
                .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1234))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // K. Test transaction signing (Ethereum)
    let ethereum_tx = format!("0x02{}", "00".repeat(100));
    
    let sign_request = serde_json::json!({
        "network": "eth",
        "index": 0,
        "unsigned_tx": ethereum_tx
    });
    
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/wallets/{}/sign", wallet_id))
                .header("Content-Type", "application/json")
                .header("X-Api-Key", "test-secret-key")
                .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1234))))
                .body(Body::from(sign_request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK, "Transaction signing should succeed");
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: Value = serde_json::from_slice(&body_bytes).unwrap();
    let signed_tx = body_json["signed_tx"].as_str().unwrap();
    
    // Signed transaction should be a valid hex string starting with 0x
    assert!(signed_tx.starts_with("0x"), "Signed tx should start with 0x");
    assert!(signed_tx.len() > 10, "Signed tx should have reasonable length");
    println!("Successfully signed Ethereum transaction: {}", &signed_tx[..50]);

    // L. Test signing with invalid transaction format
    let invalid_sign_request = serde_json::json!({
        "network": "eth",
        "index": 0,
        "unsigned_tx": "0xinvalid"
    });
    
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/wallets/{}/sign", wallet_id))
                .header("Content-Type", "application/json")
                .header("X-Api-Key", "test-secret-key")
                .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1234))))
                .body(Body::from(invalid_sign_request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    
    // Should fail due to invalid transaction format
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    println!("Integration test passed!");
}

#[tokio::test]
async fn grpc_integration_test() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    use testcontainers::{GenericImage, ImageExt, runners::AsyncRunner};
    use testcontainers_modules::postgres::Postgres;

    // 1. Start Containers
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

    let vault_image = GenericImage::new("hashicorp/vault", "latest")
        .with_env_var("VAULT_DEV_ROOT_TOKEN_ID", "root")
        .with_env_var("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:8200");

    let vault_container = vault_image.start().await.expect("Failed to start vault");
    let vault_port = vault_container
        .get_host_port_ipv4(8200)
        .await
        .expect("Failed to get Vault port");
    let vault_addr = format!("http://127.0.0.1:{}", vault_port);

    // 2. Setup Vault
    let client = reqwest::Client::new();
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

    client
        .post(format!("{}/v1/sys/mounts/transit", vault_addr))
        .header("X-Vault-Token", "root")
        .json(&serde_json::json!({ "type": "transit" }))
        .send()
        .await
        .expect("Failed to enable transit")
        .error_for_status()
        .unwrap();

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
            port: 0, // Let OS assign port
            grpc_port: Some(0), // Let OS assign port
            api_key: Some("test-secret-key".to_string()),
            rate_limit: config::RateLimitConfig {
                enabled: false, // Disable rate limiting for tests
                requests_per_second: 10,
                burst_size: 5,
            },
            trusted_proxies: vec![],
        },
        database: config::DatabaseConfig {
            url: db_url.clone(),
            pool_size: 5,
            min_connections: 1,
            max_lifetime_secs: 60,
            idle_timeout_secs: 30,
            acquire_timeout_secs: 3,
        },
        vault: config::VaultConfig {
            address: vault_addr.clone(),
            token: "root".to_string(),
            key_id: "master-key".to_string(),
        },
        redis: config::RedisConfig {
            url: "redis://127.0.0.1:6379".to_string(),
            ttl_secs: 3600,
            enabled: false, // Disable Redis for integration tests
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

    // 5. Start gRPC Server
    let grpc_port = portpicker::pick_unused_port().expect("No free ports");
    let grpc_addr = format!("127.0.0.1:{}", grpc_port);
    let grpc_socket_addr: SocketAddr = grpc_addr.parse().unwrap();

    let wallet_manager = core::WalletManager::new(vault_client.clone());
    let state = Arc::new(api::AppState {
        db: db_client,
        vault: vault_client,
        wallet_manager,
        config: config.clone(),
    });

    let grpc_service = api::MyWalletService {
        state: state.clone(),
    };

    let auth_interceptor = api::check_auth_interceptor(config.server.api_key.clone());
    let grpc_interceptor = api::combined_interceptor(auth_interceptor, None);

    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(
                api::grpc::wallet_service_server::WalletServiceServer::with_interceptor(
                    grpc_service,
                    grpc_interceptor,
                ),
            )
            .serve(grpc_socket_addr)
            .await
            .unwrap();
    });

    // Wait for server to start
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // 6. Test gRPC Client
    let mut grpc_client = timeout(
        Duration::from_secs(5),
        WalletServiceClient::connect(format!("http://{}", grpc_addr))
    )
        .await
        .expect("Timeout connecting to gRPC")
        .expect("Failed to connect to gRPC");

    // Test CreateWallet with API key
    let mut create_request = tonic::Request::new(GrpcCreateWalletRequest {
        label: "grpc-test-wallet".to_string(),
        mnemonic_length: Some(12),
    });
    create_request.metadata_mut().insert("x-api-key", "test-secret-key".parse().unwrap());

    let response = timeout(
        Duration::from_secs(5),
        grpc_client.create_wallet(create_request)
    )
        .await
        .expect("Timeout creating wallet")
        .expect("Failed to create wallet");

    let wallet_id = response.into_inner().id;
    assert!(!wallet_id.is_empty());
    println!("Created wallet via gRPC: {}", wallet_id);

    // Test GetAddress (Ethereum) with API key
    let mut address_request = tonic::Request::new(GrpcGetAddressRequest {
        wallet_id: wallet_id.clone(),
        network: "eth".to_string(),
        index: 0,
    });
    address_request.metadata_mut().insert("x-api-key", "test-secret-key".parse().unwrap());

    let response = timeout(
        Duration::from_secs(5),
        grpc_client.get_address(address_request)
    )
        .await
        .expect("Timeout getting address")
        .expect("Failed to get address");

    let address = response.into_inner().address;
    assert!(address.starts_with("0x"));
    println!("Got address via gRPC: {}", address);

    // Test unauthorized request (no API key)
    let unauthorized_request = tonic::Request::new(GrpcCreateWalletRequest {
        label: "unauthorized".to_string(),
        mnemonic_length: Some(12),
    });

    let result = grpc_client.create_wallet(unauthorized_request).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    println!("Unauthorized request correctly rejected: {}", err.message());
    
    println!("gRPC integration test passed!");
}
