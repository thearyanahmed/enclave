use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::AuthError;

#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    pub attempts: u32,
    pub reset_at: DateTime<Utc>,
}

impl RateLimitInfo {
    pub fn available_in(&self) -> i64 {
        (self.reset_at - Utc::now()).num_seconds().max(0)
    }
}

/// implement this trait for custom storage (redis, postgres, etc.)
#[async_trait]
pub trait RateLimitStore: Send + Sync {
    /// creates key with 1 attempt if it doesn't exist
    async fn increment(&self, key: &str, window_secs: i64) -> Result<RateLimitInfo, AuthError>;

    async fn get(&self, key: &str) -> Result<Option<RateLimitInfo>, AuthError>;

    async fn reset(&self, key: &str) -> Result<(), AuthError>;

    /// does not increment the counter
    async fn remaining(&self, key: &str, max_attempts: u32) -> Result<u32, AuthError> {
        Ok(self.get(key).await?.map_or(max_attempts, |info| {
            if info.reset_at < Utc::now() {
                max_attempts
            } else {
                max_attempts.saturating_sub(info.attempts)
            }
        }))
    }
}

/// for distributed systems, use a shared store like redis or postgres
#[derive(Debug, Default)]
pub struct InMemoryStore {
    entries: Arc<RwLock<HashMap<String, RateLimitInfo>>>,
}

impl InMemoryStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// call periodically in long-running applications to prevent memory growth
    pub fn cleanup_expired(&self) {
        let now = Utc::now();
        if let Ok(mut entries) = self.entries.write() {
            entries.retain(|_, info| info.reset_at > now);
        }
    }
}

#[async_trait]
#[allow(clippy::significant_drop_tightening)]
impl RateLimitStore for InMemoryStore {
    async fn increment(&self, key: &str, window_secs: i64) -> Result<RateLimitInfo, AuthError> {
        let now = Utc::now();
        let window = chrono::Duration::seconds(i64::try_from(window_secs).unwrap_or(i64::MAX));

        let mut entries = self
            .entries
            .write()
            .map_err(|_| AuthError::DatabaseError("Failed to acquire lock".to_owned()))?;

        let info = entries
            .entry(key.to_owned())
            .and_modify(|info| {
                if info.reset_at <= now {
                    // Window expired, start new one
                    info.attempts = 1;
                    info.reset_at = now + window;
                } else {
                    info.attempts += 1;
                }
            })
            .or_insert_with(|| RateLimitInfo {
                attempts: 1,
                reset_at: now + window,
            });

        Ok(info.clone())
    }

    async fn get(&self, key: &str) -> Result<Option<RateLimitInfo>, AuthError> {
        let entries = self
            .entries
            .read()
            .map_err(|_| AuthError::DatabaseError("Failed to acquire lock".to_owned()))?;

        Ok(entries.get(key).cloned())
    }

    async fn reset(&self, key: &str) -> Result<(), AuthError> {
        let mut entries = self
            .entries
            .write()
            .map_err(|_| AuthError::DatabaseError("Failed to acquire lock".to_owned()))?;

        entries.remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_store_increment() {
        let store = InMemoryStore::new();

        let info = store.increment("test-key", 60).await.unwrap();
        assert_eq!(info.attempts, 1);

        let info = store.increment("test-key", 60).await.unwrap();
        assert_eq!(info.attempts, 2);

        let info = store.increment("test-key", 60).await.unwrap();
        assert_eq!(info.attempts, 3);
    }

    #[tokio::test]
    async fn test_in_memory_store_get() {
        let store = InMemoryStore::new();

        // Key doesn't exist
        let info = store.get("nonexistent").await.unwrap();
        assert!(info.is_none());

        // After increment
        store.increment("test-key", 60).await.unwrap();
        let info = store.get("test-key").await.unwrap();
        assert!(info.is_some());
        assert_eq!(info.unwrap().attempts, 1);
    }

    #[tokio::test]
    async fn test_in_memory_store_reset() {
        let store = InMemoryStore::new();

        store.increment("test-key", 60).await.unwrap();
        store.increment("test-key", 60).await.unwrap();

        let info = store.get("test-key").await.unwrap();
        assert_eq!(info.unwrap().attempts, 2);

        store.reset("test-key").await.unwrap();

        let info = store.get("test-key").await.unwrap();
        assert!(info.is_none());
    }

    #[tokio::test]
    async fn test_in_memory_store_remaining() {
        let store = InMemoryStore::new();

        // Full capacity
        let remaining = store.remaining("test-key", 5).await.unwrap();
        assert_eq!(remaining, 5);

        // After some attempts
        store.increment("test-key", 60).await.unwrap();
        store.increment("test-key", 60).await.unwrap();

        let remaining = store.remaining("test-key", 5).await.unwrap();
        assert_eq!(remaining, 3);
    }
}
