use std::collections::HashMap;
use std::sync::Arc;

use super::limit::Limit;
use super::store::RateLimitStore;
use crate::AuthError;

/// Result of a rate limit check.
#[derive(Debug, Clone)]
pub enum RateLimitResult {
    /// Request is allowed. Contains remaining attempts.
    Allowed {
        remaining: u32,
        reset_at: chrono::DateTime<chrono::Utc>,
    },
    /// Request is rate limited.
    Limited { retry_after: i64, message: String },
}

impl RateLimitResult {
    /// Returns true if the request is allowed.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }

    /// Returns true if the request is rate limited.
    pub fn is_limited(&self) -> bool {
        matches!(self, Self::Limited { .. })
    }

    /// Returns the retry-after value in seconds if rate limited.
    pub fn retry_after(&self) -> Option<i64> {
        match self {
            Self::Limited { retry_after, .. } => Some(*retry_after),
            Self::Allowed { .. } => None,
        }
    }
}

/// Rate limiter with named limit configurations.
///
/// Provides a Laravel-inspired API for defining and checking rate limits.
///
/// # Example
///
/// ```rust
/// use enclave::rate_limit::{RateLimiter, Limit, InMemoryStore};
/// use std::sync::Arc;
///
/// let store = Arc::new(InMemoryStore::new());
/// let limiter = RateLimiter::new(store)
///     .for_("api", Limit::per_minute(60))
///     .for_("login", Limit::per_minute(5));
/// ```
#[derive(Clone)]
pub struct RateLimiter {
    store: Arc<dyn RateLimitStore>,
    limits: HashMap<String, Limit>,
}

impl RateLimiter {
    /// Creates a new rate limiter with the specified store.
    #[must_use]
    pub fn new(store: Arc<dyn RateLimitStore>) -> Self {
        Self {
            store,
            limits: HashMap::new(),
        }
    }

    /// Registers a named rate limit.
    ///
    /// # Example
    ///
    /// ```rust
    /// use enclave::rate_limit::{RateLimiter, Limit, InMemoryStore};
    /// use std::sync::Arc;
    ///
    /// let store = Arc::new(InMemoryStore::new());
    /// let limiter = RateLimiter::new(store)
    ///     .for_("api", Limit::per_minute(60))
    ///     .for_("login", Limit::per_minute(5).by_ip());
    /// ```
    #[must_use]
    pub fn for_(mut self, name: impl Into<String>, limit: Limit) -> Self {
        self.limits.insert(name.into(), limit);
        self
    }

    /// Gets a registered limit by name.
    pub fn get_limit(&self, name: &str) -> Option<&Limit> {
        self.limits.get(name)
    }

    /// Returns a reference to the underlying store.
    pub fn store(&self) -> &Arc<dyn RateLimitStore> {
        &self.store
    }

    /// Attempts to execute an action with rate limiting.
    ///
    /// Similar to Laravel's `RateLimiter::attempt()`.
    ///
    /// Returns `Ok(result)` if allowed, or the rate limit result if blocked.
    pub async fn attempt<T, F, Fut>(
        &self,
        limit_name: &str,
        key: &str,
        action: F,
    ) -> Result<Result<T, RateLimitResult>, AuthError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let result = self.hit(limit_name, key).await?;

        match result {
            RateLimitResult::Allowed { .. } => Ok(Ok(action().await)),
            limited @ RateLimitResult::Limited { .. } => Ok(Err(limited)),
        }
    }

    /// Records a hit against a rate limit and checks if allowed.
    ///
    /// This increments the counter and returns whether the request should be allowed.
    pub async fn hit(&self, limit_name: &str, key: &str) -> Result<RateLimitResult, AuthError> {
        let limit = self.limits.get(limit_name).ok_or_else(|| {
            AuthError::DatabaseError(format!("Rate limit '{limit_name}' not configured"))
        })?;

        let full_key = format!("{limit_name}:{key}");
        let info = self.store.increment(&full_key, limit.window_secs()).await?;

        if info.attempts > limit.max_attempts {
            let message = limit
                .get_message()
                .unwrap_or("Too many requests. Please try again later.")
                .to_owned();

            Ok(RateLimitResult::Limited {
                retry_after: info.available_in(),
                message,
            })
        } else {
            Ok(RateLimitResult::Allowed {
                remaining: limit.max_attempts - info.attempts,
                reset_at: info.reset_at,
            })
        }
    }

    /// Checks if a key has exceeded the rate limit without incrementing.
    pub async fn too_many_attempts(&self, limit_name: &str, key: &str) -> Result<bool, AuthError> {
        let limit = self.limits.get(limit_name).ok_or_else(|| {
            AuthError::DatabaseError(format!("Rate limit '{limit_name}' not configured"))
        })?;

        let full_key = format!("{limit_name}:{key}");
        let remaining = self.store.remaining(&full_key, limit.max_attempts).await?;

        Ok(remaining == 0)
    }

    /// Returns the remaining attempts for a key.
    pub async fn remaining(&self, limit_name: &str, key: &str) -> Result<u32, AuthError> {
        let limit = self.limits.get(limit_name).ok_or_else(|| {
            AuthError::DatabaseError(format!("Rate limit '{limit_name}' not configured"))
        })?;

        let full_key = format!("{limit_name}:{key}");
        self.store.remaining(&full_key, limit.max_attempts).await
    }

    /// Returns seconds until the rate limit resets for a key.
    pub async fn available_in(&self, limit_name: &str, key: &str) -> Result<i64, AuthError> {
        let full_key = format!("{limit_name}:{key}");

        Ok(self
            .store
            .get(&full_key)
            .await?
            .map_or(0, |info| info.available_in()))
    }

    /// Clears the rate limit for a key.
    pub async fn clear(&self, limit_name: &str, key: &str) -> Result<(), AuthError> {
        let full_key = format!("{limit_name}:{key}");
        self.store.reset(&full_key).await
    }

    /// Creates a throttle middleware for actix-web.
    #[cfg(feature = "actix")]
    pub fn throttle(&self, limit_name: &str) -> super::middleware::Throttle {
        super::middleware::Throttle::new(
            Arc::clone(&self.store),
            self.limits.get(limit_name).cloned(),
            limit_name.to_owned(),
        )
    }
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("limits", &self.limits.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rate_limit::InMemoryStore;

    #[tokio::test]
    async fn test_rate_limiter_hit() {
        let store = Arc::new(InMemoryStore::new());
        let limiter = RateLimiter::new(store).for_("test", Limit::per_minute(3));

        // First 3 should be allowed
        for i in 0..3 {
            let result = limiter.hit("test", "user-1").await.unwrap();
            assert!(result.is_allowed(), "Request {} should be allowed", i + 1);
        }

        // 4th should be rate limited
        let result = limiter.hit("test", "user-1").await.unwrap();
        assert!(result.is_limited());
    }

    #[tokio::test]
    async fn test_rate_limiter_different_keys() {
        let store = Arc::new(InMemoryStore::new());
        let limiter = RateLimiter::new(store).for_("test", Limit::per_minute(2));

        // Each key has its own counter
        limiter.hit("test", "user-1").await.unwrap();
        limiter.hit("test", "user-1").await.unwrap();
        let result = limiter.hit("test", "user-1").await.unwrap();
        assert!(result.is_limited());

        // Different key should still be allowed
        let result = limiter.hit("test", "user-2").await.unwrap();
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_rate_limiter_remaining() {
        let store = Arc::new(InMemoryStore::new());
        let limiter = RateLimiter::new(store).for_("test", Limit::per_minute(5));

        assert_eq!(limiter.remaining("test", "user-1").await.unwrap(), 5);

        limiter.hit("test", "user-1").await.unwrap();
        limiter.hit("test", "user-1").await.unwrap();

        assert_eq!(limiter.remaining("test", "user-1").await.unwrap(), 3);
    }

    #[tokio::test]
    async fn test_rate_limiter_clear() {
        let store = Arc::new(InMemoryStore::new());
        let limiter = RateLimiter::new(store).for_("test", Limit::per_minute(2));

        limiter.hit("test", "user-1").await.unwrap();
        limiter.hit("test", "user-1").await.unwrap();

        // Should be rate limited
        let result = limiter.hit("test", "user-1").await.unwrap();
        assert!(result.is_limited());

        // Clear and try again
        limiter.clear("test", "user-1").await.unwrap();

        let result = limiter.hit("test", "user-1").await.unwrap();
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_rate_limiter_attempt() {
        let store = Arc::new(InMemoryStore::new());
        let limiter = RateLimiter::new(store).for_("test", Limit::per_minute(2));

        // First attempt should succeed
        let result = limiter
            .attempt("test", "user-1", || async { 42 })
            .await
            .unwrap();
        assert_eq!(result.unwrap(), 42);

        // Second attempt should succeed
        let result = limiter
            .attempt("test", "user-1", || async { 43 })
            .await
            .unwrap();
        assert_eq!(result.unwrap(), 43);

        // Third attempt should be rate limited
        let result = limiter
            .attempt("test", "user-1", || async { 44 })
            .await
            .unwrap();
        assert!(result.is_err());
    }
}
