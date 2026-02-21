//! Redis client for caching
//!
//! Provides caching for:
//! - Derived addresses
//! - Health check status
//! - Future: balances, transaction history

use redis::{aio::ConnectionManager, AsyncCommands};
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;

pub use redis::RedisError;

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("Redis error: {0}")]
    Redis(#[from] RedisError),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Deserialization error: {0}")]
    Deserialization(String),
}

#[derive(Clone)]
pub struct RedisClient {
    connection: ConnectionManager,
    default_ttl: Duration,
}

impl RedisClient {
    /// Create new Redis client
    pub async fn new(redis_url: &str) -> Result<Self, RedisError> {
        let client = redis::Client::open(redis_url)?;
        let connection = ConnectionManager::new(client).await?;
        
        Ok(Self {
            connection,
            default_ttl: Duration::from_secs(3600), // 1 hour default
        })
    }

    /// Create new Redis client with custom TTL
    pub async fn with_ttl(redis_url: &str, ttl: Duration) -> Result<Self, RedisError> {
        let client = redis::Client::open(redis_url)?;
        let connection = ConnectionManager::new(client).await?;
        
        Ok(Self {
            connection,
            default_ttl: ttl,
        })
    }

    /// Set value with default TTL
    pub async fn set<T: Serialize>(&self, key: &str, value: &T) -> Result<(), CacheError> {
        let serialized = serde_json::to_string(value)
            .map_err(|e| CacheError::Serialization(e.to_string()))?;
        
        let mut conn = self.connection.clone();
        conn.set_ex::<&str, String, ()>(key, serialized, self.default_ttl.as_secs() as u64).await?;
        Ok(())
    }

    /// Set value with custom TTL (in seconds)
    pub async fn set_with_ttl<T: Serialize>(
        &self,
        key: &str,
        value: &T,
        ttl_secs: u64,
    ) -> Result<(), CacheError> {
        let serialized = serde_json::to_string(value)
            .map_err(|e| CacheError::Serialization(e.to_string()))?;
        
        let mut conn = self.connection.clone();
        conn.set_ex::<&str, String, ()>(key, serialized, ttl_secs).await?;
        Ok(())
    }

    /// Get value from cache
    pub async fn get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, CacheError> {
        let mut conn = self.connection.clone();
        let value: Option<String> = conn.get(key).await?;
        
        match value {
            Some(v) => {
                let deserialized = serde_json::from_str(&v)
                    .map_err(|e| CacheError::Deserialization(e.to_string()))?;
                Ok(Some(deserialized))
            }
            None => Ok(None),
        }
    }

    /// Delete key from cache
    pub async fn delete(&self, key: &str) -> Result<(), CacheError> {
        let mut conn = self.connection.clone();
        conn.del::<&str, usize>(key).await?;
        Ok(())
    }

    /// Check if key exists
    pub async fn exists(&self, key: &str) -> Result<bool, CacheError> {
        let mut conn = self.connection.clone();
        let exists: bool = conn.exists(key).await?;
        Ok(exists)
    }

    /// Ping Redis server
    pub async fn ping(&self) -> Result<String, CacheError> {
        let mut conn = self.connection.clone();
        let pong: String = conn.ping().await?;
        Ok(pong)
    }

    /// Get cache key for derived address
    pub fn address_key(wallet_id: &str, network: &str, index: u32) -> String {
        format!("addr:{}:{}:{}", wallet_id, network, index)
    }

    /// Get cache key for health status
    pub fn health_key(component: &str) -> String {
        format!("health:{}", component)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require a running Redis instance
    // Run with: docker run -d -p 6379:6379 redis:latest

    #[tokio::test]
    #[ignore = "requires Redis server"]
    async fn test_redis_set_and_get() {
        let client = RedisClient::new("redis://127.0.0.1:6379").await.unwrap();
        
        // Test set and get
        let key = "test:key";
        let value = "test_value";
        
        client.set(key, &value).await.unwrap();
        let result: Option<String> = client.get(key).await.unwrap();
        
        assert_eq!(result, Some(value.to_string()));
        
        // Cleanup
        client.delete(key).await.unwrap();
    }

    #[test]
    fn test_redis_key_generation() {
        assert_eq!(
            RedisClient::address_key("uuid-123", "eth", 0),
            "addr:uuid-123:eth:0"
        );
        assert_eq!(
            RedisClient::health_key("database"),
            "health:database"
        );
    }
}
