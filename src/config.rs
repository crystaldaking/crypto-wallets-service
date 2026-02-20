use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;
use std::fmt;

#[derive(Debug, Deserialize, Clone)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests_per_second: u32,
    pub burst_size: u32,
}

#[derive(Deserialize, Clone)]
pub struct ServerConfig {
    pub port: u16,
    pub api_key: Option<String>,
    pub rate_limit: RateLimitConfig,
    /// List of trusted proxy CIDRs (e.g., ["10.0.0.0/8", "127.0.0.1"])
    /// When empty, falls back to X-Real-Ip or direct connection
    #[serde(default)]
    pub trusted_proxies: Vec<ipnet::IpNet>,
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig")
            .field("port", &self.port)
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .field("rate_limit", &self.rate_limit)
            .field("trusted_proxies", &self.trusted_proxies)
            .finish()
    }
}

#[derive(Deserialize, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    /// Maximum number of connections in the pool
    /// Default: 20 (suitable for production workloads)
    /// For high-load systems, consider 50+ connections
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,
}

impl fmt::Debug for DatabaseConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseConfig")
            .field("url", &"[REDACTED]")
            .field("pool_size", &self.pool_size)
            .finish()
    }
}

fn default_pool_size() -> u32 {
    20
}

#[derive(Deserialize, Clone)]
pub struct VaultConfig {
    pub address: String,
    pub token: String,
    pub key_id: String,
}

impl fmt::Debug for VaultConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultConfig")
            .field("address", &self.address)
            .field("token", &"[REDACTED]")
            .field("key_id", &self.key_id)
            .finish()
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub vault: VaultConfig,
}

impl AppConfig {
    pub fn build() -> Result<Self, ConfigError> {
        let s = Config::builder()
            .add_source(File::with_name("config/default").required(false))
            .add_source(Environment::with_prefix("APP").separator("__"))
            .build()?;

        s.try_deserialize()
    }
}
