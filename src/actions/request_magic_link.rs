#[cfg(feature = "rate_limit")]
use std::sync::Arc;

use chrono::{Duration, Utc};

#[cfg(feature = "rate_limit")]
use crate::rate_limit::RateLimitStore;
use crate::{AuthError, MagicLinkRepository, MagicLinkToken, UserRepository};

#[derive(Debug, Clone)]
pub struct MagicLinkConfig {
    pub magic_link_expiry: Duration,
}

impl Default for MagicLinkConfig {
    fn default() -> Self {
        Self {
            magic_link_expiry: Duration::minutes(15),
        }
    }
}

impl MagicLinkConfig {
    #[cfg(feature = "magic_link")]
    pub fn from_token_config(tokens: &crate::config::TokenConfig) -> Self {
        Self {
            magic_link_expiry: tokens.magic_link_expiry,
        }
    }
}

#[cfg(feature = "rate_limit")]
#[derive(Clone)]
pub struct MagicLinkRateLimitConfig {
    pub store: Arc<dyn RateLimitStore>,
    pub max_requests: u32,
    pub window: Duration,
}

#[cfg(feature = "rate_limit")]
impl MagicLinkRateLimitConfig {
    pub fn new(store: Arc<dyn RateLimitStore>) -> Self {
        Self {
            store,
            max_requests: 5,
            window: Duration::hours(1),
        }
    }

    #[must_use]
    pub fn max_requests(mut self, max_requests: u32) -> Self {
        self.max_requests = max_requests;
        self
    }

    #[must_use]
    pub fn window(mut self, window: Duration) -> Self {
        self.window = window;
        self
    }
}

pub struct RequestMagicLinkAction<U, M>
where
    U: UserRepository,
    M: MagicLinkRepository,
{
    user_repository: U,
    magic_link_repository: M,
    #[cfg(feature = "rate_limit")]
    rate_limit: Option<MagicLinkRateLimitConfig>,
    config: MagicLinkConfig,
}

impl<U: UserRepository, M: MagicLinkRepository> RequestMagicLinkAction<U, M> {
    /// Creates a new `RequestMagicLinkAction` with default configuration.
    ///
    /// Default: 15 minute token expiry. For custom settings, use [`with_config`].
    ///
    /// [`with_config`]: Self::with_config
    pub fn new(user_repository: U, magic_link_repository: M) -> Self {
        Self::with_config(
            user_repository,
            magic_link_repository,
            MagicLinkConfig::default(),
        )
    }

    /// Creates a new `RequestMagicLinkAction` with custom configuration.
    pub fn with_config(
        user_repository: U,
        magic_link_repository: M,
        config: MagicLinkConfig,
    ) -> Self {
        RequestMagicLinkAction {
            user_repository,
            magic_link_repository,
            #[cfg(feature = "rate_limit")]
            rate_limit: None,
            config,
        }
    }

    #[must_use]
    pub fn config(mut self, config: MagicLinkConfig) -> Self {
        self.config = config;
        self
    }
}

#[cfg(feature = "rate_limit")]
impl<U: UserRepository, M: MagicLinkRepository> RequestMagicLinkAction<U, M> {
    /// Enables rate limiting for magic link requests.
    ///
    /// Default: 5 requests per hour. Rate limiting is keyed by the provided
    /// `rate_limit_key` in [`execute`] (typically the client IP address).
    ///
    /// [`execute`]: Self::execute
    #[must_use]
    pub fn with_rate_limit(mut self, config: MagicLinkRateLimitConfig) -> Self {
        self.rate_limit = Some(config);
        self
    }

    /// Requests a magic link token for passwordless authentication.
    ///
    /// Rate limiting is applied by the provided key (typically client IP).
    ///
    /// # Returns
    ///
    /// - `Ok(Some(token))` - user exists and magic link was created
    /// - `Ok(None)` - no user with that email (prevents user enumeration)
    /// - `Err(AuthError::TooManyAttempts)` - rate limited
    /// - `Err(_)` - database or other errors
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "request_magic_link", skip_all, err)
    )]
    pub async fn execute(
        &self,
        email: &str,
        rate_limit_key: &str,
    ) -> Result<Option<MagicLinkToken>, AuthError> {
        if let Some(ref rate_limit) = self.rate_limit {
            let window_secs = u64::try_from(rate_limit.window.num_seconds().max(1)).unwrap_or(60);
            let key = format!("magic_link:{rate_limit_key}");
            let info = rate_limit.store.increment(&key, window_secs).await?;

            if info.attempts > rate_limit.max_requests {
                return Err(AuthError::TooManyAttempts);
            }
        }

        self.execute_internal(email).await
    }
}

#[cfg(not(feature = "rate_limit"))]
impl<U: UserRepository, M: MagicLinkRepository> RequestMagicLinkAction<U, M> {
    /// Requests a magic link token for passwordless authentication.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(token))` - user exists and magic link was created
    /// - `Ok(None)` - no user with that email (prevents user enumeration)
    /// - `Err(_)` - database or other errors
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "request_magic_link", skip_all, err)
    )]
    pub async fn execute(&self, email: &str) -> Result<Option<MagicLinkToken>, AuthError> {
        self.execute_internal(email).await
    }
}

impl<U: UserRepository, M: MagicLinkRepository> RequestMagicLinkAction<U, M> {
    async fn execute_internal(&self, email: &str) -> Result<Option<MagicLinkToken>, AuthError> {
        let user = self.user_repository.find_user_by_email(email).await?;

        match user {
            Some(user) => {
                let expires_at = Utc::now() + self.config.magic_link_expiry;
                let token = self
                    .magic_link_repository
                    .create_magic_link_token(user.id, expires_at)
                    .await?;

                log::info!(
                    target: "enclave_auth",
                    "msg=\"magic link requested\""
                );

                Ok(Some(token))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthUser, MockMagicLinkRepository, MockUserRepository};

    #[cfg(not(feature = "rate_limit"))]
    #[tokio::test]
    async fn test_request_magic_link_creates_token() {
        let user_repo = MockUserRepository::new();
        let magic_link_repo = MockMagicLinkRepository::new();

        let user = AuthUser::mock_from_email("user@example.com");
        user_repo.users.lock().unwrap().push(user.clone());

        let action = RequestMagicLinkAction::new(user_repo, magic_link_repo);
        let result = action.execute("user@example.com").await;

        assert!(result.is_ok());
        let token = result.unwrap();
        assert!(token.is_some());
        let token = token.unwrap();
        assert_eq!(token.user_id, user.id);
        assert!(!token.token.is_empty());
    }

    #[cfg(not(feature = "rate_limit"))]
    #[tokio::test]
    async fn test_request_magic_link_user_not_found_returns_none() {
        let user_repo = MockUserRepository::new();
        let magic_link_repo = MockMagicLinkRepository::new();

        let action = RequestMagicLinkAction::new(user_repo, magic_link_repo);
        let result = action.execute("nonexistent@example.com").await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[cfg(not(feature = "rate_limit"))]
    #[tokio::test]
    async fn test_request_magic_link_default_expiry() {
        let user_repo = MockUserRepository::new();
        let magic_link_repo = MockMagicLinkRepository::new();

        let user = AuthUser::mock_from_email("user@example.com");
        user_repo.users.lock().unwrap().push(user);

        let action = RequestMagicLinkAction::new(user_repo, magic_link_repo);
        let result = action.execute("user@example.com").await;

        let token = result.unwrap().unwrap();
        let now = Utc::now();
        // Token should expire in approximately 15 minutes
        let duration = token.expires_at - now;
        assert!(duration.num_minutes() >= 14);
        assert!(duration.num_minutes() <= 15);
    }

    #[cfg(feature = "rate_limit")]
    mod rate_limit_tests {
        use std::sync::Arc;

        use super::*;
        use crate::rate_limit::InMemoryStore;

        #[tokio::test]
        async fn test_request_magic_link_creates_token() {
            let user_repo = MockUserRepository::new();
            let magic_link_repo = MockMagicLinkRepository::new();

            let user = AuthUser::mock_from_email("user@example.com");
            user_repo.users.lock().unwrap().push(user.clone());

            let action = RequestMagicLinkAction::new(user_repo, magic_link_repo);
            let result = action.execute("user@example.com", "127.0.0.1").await;

            assert!(result.is_ok());
            let token = result.unwrap();
            assert!(token.is_some());
            let token = token.unwrap();
            assert_eq!(token.user_id, user.id);
            assert!(!token.token.is_empty());
        }

        #[tokio::test]
        async fn test_request_magic_link_rate_limited() {
            let user_repo = MockUserRepository::new();
            let magic_link_repo = MockMagicLinkRepository::new();

            let user = AuthUser::mock_from_email("user@example.com");
            user_repo.users.lock().unwrap().push(user);

            let rate_limit = MagicLinkRateLimitConfig::new(Arc::new(InMemoryStore::new()))
                .max_requests(2)
                .window(Duration::hours(1));

            let action =
                RequestMagicLinkAction::new(user_repo, magic_link_repo).with_rate_limit(rate_limit);

            // First two requests should succeed
            let result1 = action.execute("user@example.com", "192.168.1.1").await;
            assert!(result1.is_ok());

            let result2 = action.execute("user@example.com", "192.168.1.1").await;
            assert!(result2.is_ok());

            // Third request should be rate limited
            let result3 = action.execute("user@example.com", "192.168.1.1").await;
            assert!(result3.is_err());
            assert_eq!(result3.unwrap_err(), AuthError::TooManyAttempts);
        }
    }
}
