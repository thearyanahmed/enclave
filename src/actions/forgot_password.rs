use crate::{AuthError, PasswordResetRepository, PasswordResetToken, UserRepository};
use chrono::{Duration, Utc};

#[cfg(feature = "rate_limit")]
use crate::rate_limit::RateLimitStore;
#[cfg(feature = "rate_limit")]
use std::sync::Arc;

/// Configuration for password reset behavior.
#[derive(Debug, Clone)]
pub struct ForgotPasswordConfig {
    /// How long password reset tokens remain valid.
    ///
    /// Default: 1 hour
    pub password_reset_expiry: Duration,
}

impl Default for ForgotPasswordConfig {
    fn default() -> Self {
        Self {
            password_reset_expiry: Duration::hours(1),
        }
    }
}

impl ForgotPasswordConfig {
    /// Creates config from a `TokenConfig`.
    pub fn from_token_config(tokens: &crate::config::TokenConfig) -> Self {
        Self {
            password_reset_expiry: tokens.password_reset_expiry,
        }
    }
}

/// Configuration for rate limiting.
///
/// # Example
///
/// ```rust,ignore
/// use enclave::actions::RateLimitConfig;
/// use enclave::rate_limit::InMemoryStore;
/// use chrono::Duration;
/// use std::sync::Arc;
///
/// // Default: 120 requests per minute
/// let config = RateLimitConfig::new(Arc::new(InMemoryStore::new()));
///
/// // Custom: 60 requests per hour
/// let config = RateLimitConfig::new(Arc::new(InMemoryStore::new()))
///     .max_requests(60)
///     .window(Duration::hours(1));
/// ```
#[cfg(feature = "rate_limit")]
#[derive(Clone)]
pub struct RateLimitConfig {
    /// The store to use for tracking rate limits.
    pub store: Arc<dyn RateLimitStore>,

    /// Maximum number of requests allowed per window.
    ///
    /// Default: 120
    pub max_requests: u32,

    /// Time window for rate limiting.
    ///
    /// Default: 1 minute
    pub window: Duration,
}

#[cfg(feature = "rate_limit")]
impl RateLimitConfig {
    /// Creates a new rate limit config with default settings (120 requests per minute).
    pub fn new(store: Arc<dyn RateLimitStore>) -> Self {
        Self {
            store,
            max_requests: 120,
            window: Duration::minutes(1),
        }
    }

    /// Sets the maximum number of requests allowed per window.
    #[must_use]
    pub fn max_requests(mut self, max_requests: u32) -> Self {
        self.max_requests = max_requests;
        self
    }

    /// Sets the time window for rate limiting.
    #[must_use]
    pub fn window(mut self, window: Duration) -> Self {
        self.window = window;
        self
    }
}

pub struct ForgotPasswordAction<U, P>
where
    U: UserRepository,
    P: PasswordResetRepository,
{
    user_repository: U,
    reset_repository: P,
    #[cfg(feature = "rate_limit")]
    rate_limit: Option<RateLimitConfig>,
    config: ForgotPasswordConfig,
}

impl<U: UserRepository, P: PasswordResetRepository> ForgotPasswordAction<U, P> {
    pub fn new(user_repository: U, reset_repository: P) -> Self {
        Self::with_config(
            user_repository,
            reset_repository,
            ForgotPasswordConfig::default(),
        )
    }

    pub fn with_config(
        user_repository: U,
        reset_repository: P,
        config: ForgotPasswordConfig,
    ) -> Self {
        ForgotPasswordAction {
            user_repository,
            reset_repository,
            #[cfg(feature = "rate_limit")]
            rate_limit: None,
            config,
        }
    }

    /// Sets the configuration.
    #[must_use]
    pub fn config(mut self, config: ForgotPasswordConfig) -> Self {
        self.config = config;
        self
    }
}

#[cfg(feature = "rate_limit")]
impl<U: UserRepository, P: PasswordResetRepository> ForgotPasswordAction<U, P> {
    /// Adds rate limiting to the password reset action.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use enclave::actions::{ForgotPasswordAction, RateLimitConfig};
    /// use enclave::rate_limit::InMemoryStore;
    /// use chrono::Duration;
    /// use std::sync::Arc;
    ///
    /// // Default: 120 requests per minute
    /// let action = ForgotPasswordAction::new(user_repo, reset_repo)
    ///     .with_rate_limit(RateLimitConfig::new(Arc::new(InMemoryStore::new())));
    ///
    /// // Custom: 5 requests per hour
    /// let action = ForgotPasswordAction::new(user_repo, reset_repo)
    ///     .with_rate_limit(
    ///         RateLimitConfig::new(Arc::new(InMemoryStore::new()))
    ///             .max_requests(5)
    ///             .window(Duration::hours(1))
    ///     );
    /// ```
    #[must_use]
    pub fn with_rate_limit(mut self, config: RateLimitConfig) -> Self {
        self.rate_limit = Some(config);
        self
    }

    /// Initiates a password reset for the given email.
    ///
    /// Rate limiting is applied by the provided key (typically client IP).
    ///
    /// Returns `Ok(Some(token))` if a user with that email exists and a reset token was created.
    /// Returns `Ok(None)` if no user exists with that email (prevents user enumeration).
    /// Returns `Err(AuthError::TooManyAttempts)` if rate limited.
    /// Returns `Err` for other errors (database failures, etc.).
    ///
    /// # Security
    ///
    /// This method intentionally does not reveal whether a user exists.
    /// The rate limit response is the same whether or not the email exists.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "forgot_password", skip_all, err)
    )]
    pub async fn execute(
        &self,
        email: &str,
        rate_limit_key: &str,
    ) -> Result<Option<PasswordResetToken>, AuthError> {
        if let Some(ref rate_limit) = self.rate_limit {
            let window_secs = u64::try_from(rate_limit.window.num_seconds().max(1)).unwrap_or(60);
            let key = format!("forgot_password:{rate_limit_key}");
            let info = rate_limit.store.increment(&key, window_secs).await?;

            if info.attempts > rate_limit.max_requests {
                return Err(AuthError::TooManyAttempts);
            }
        }

        self.execute_internal(email).await
    }
}

#[cfg(not(feature = "rate_limit"))]
impl<U: UserRepository, P: PasswordResetRepository> ForgotPasswordAction<U, P> {
    /// Initiates a password reset for the given email.
    ///
    /// Returns `Ok(Some(token))` if a user with that email exists and a reset token was created.
    /// Returns `Ok(None)` if no user exists with that email (prevents user enumeration).
    /// Returns `Err` only for actual errors (database failures, etc.).
    ///
    /// # Security
    ///
    /// This method intentionally does not reveal whether a user exists.
    /// Always show a generic message like "If an account exists, a reset email has been sent"
    /// regardless of the return value.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "forgot_password", skip_all, err)
    )]
    pub async fn execute(&self, email: &str) -> Result<Option<PasswordResetToken>, AuthError> {
        self.execute_internal(email).await
    }
}

impl<U: UserRepository, P: PasswordResetRepository> ForgotPasswordAction<U, P> {
    async fn execute_internal(&self, email: &str) -> Result<Option<PasswordResetToken>, AuthError> {
        let user = self.user_repository.find_user_by_email(email).await?;

        match user {
            Some(user) => {
                let expires_at = Utc::now() + self.config.password_reset_expiry;
                let token = self
                    .reset_repository
                    .create_reset_token(user.id, expires_at)
                    .await?;

                log::info!(
                    target: "enclave_auth",
                    "msg=\"password_reset_requested\""
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
    use crate::{MockPasswordResetRepository, MockUserRepository, User};

    #[cfg(not(feature = "rate_limit"))]
    #[tokio::test]
    async fn test_forgot_password_creates_token() {
        let user_repo = MockUserRepository::new();
        let reset_repo = MockPasswordResetRepository::new();

        let user = User::mock_from_email("user@example.com");
        user_repo.users.lock().unwrap().push(user.clone());

        let action = ForgotPasswordAction::new(user_repo, reset_repo);
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
    async fn test_forgot_password_user_not_found_returns_none() {
        let user_repo = MockUserRepository::new();
        let reset_repo = MockPasswordResetRepository::new();

        let action = ForgotPasswordAction::new(user_repo, reset_repo);
        let result = action.execute("nonexistent@example.com").await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[cfg(feature = "rate_limit")]
    mod rate_limit_tests {
        use super::*;
        use crate::rate_limit::InMemoryStore;
        use std::sync::Arc;

        #[tokio::test]
        async fn test_forgot_password_creates_token() {
            let user_repo = MockUserRepository::new();
            let reset_repo = MockPasswordResetRepository::new();

            let user = User::mock_from_email("user@example.com");
            user_repo.users.lock().unwrap().push(user.clone());

            let action = ForgotPasswordAction::new(user_repo, reset_repo);
            let result = action.execute("user@example.com", "127.0.0.1").await;

            assert!(result.is_ok());
            let token = result.unwrap();
            assert!(token.is_some());
            let token = token.unwrap();
            assert_eq!(token.user_id, user.id);
            assert!(!token.token.is_empty());
        }

        #[tokio::test]
        async fn test_forgot_password_user_not_found_returns_none() {
            let user_repo = MockUserRepository::new();
            let reset_repo = MockPasswordResetRepository::new();

            let action = ForgotPasswordAction::new(user_repo, reset_repo);
            let result = action.execute("nonexistent@example.com", "127.0.0.1").await;

            assert!(result.is_ok());
            assert!(result.unwrap().is_none());
        }

        #[tokio::test]
        async fn test_forgot_password_rate_limited() {
            let user_repo = MockUserRepository::new();
            let reset_repo = MockPasswordResetRepository::new();

            let user = User::mock_from_email("user@example.com");
            user_repo.users.lock().unwrap().push(user);

            let rate_limit = RateLimitConfig::new(Arc::new(InMemoryStore::new()))
                .max_requests(2)
                .window(Duration::minutes(1));

            let action =
                ForgotPasswordAction::new(user_repo, reset_repo).with_rate_limit(rate_limit);

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

        #[tokio::test]
        async fn test_forgot_password_rate_limit_different_ips() {
            let user_repo = MockUserRepository::new();
            let reset_repo = MockPasswordResetRepository::new();

            let user = User::mock_from_email("user@example.com");
            user_repo.users.lock().unwrap().push(user);

            let rate_limit = RateLimitConfig::new(Arc::new(InMemoryStore::new()))
                .max_requests(1)
                .window(Duration::minutes(1));

            let action =
                ForgotPasswordAction::new(user_repo, reset_repo).with_rate_limit(rate_limit);

            // First IP uses its quota
            let result1 = action.execute("user@example.com", "192.168.1.1").await;
            assert!(result1.is_ok());

            let result2 = action.execute("user@example.com", "192.168.1.1").await;
            assert_eq!(result2.unwrap_err(), AuthError::TooManyAttempts);

            // Second IP should still work
            let result3 = action.execute("user@example.com", "192.168.1.2").await;
            assert!(result3.is_ok());
        }

        #[tokio::test]
        async fn test_forgot_password_rate_limit_nonexistent_user() {
            let user_repo = MockUserRepository::new();
            let reset_repo = MockPasswordResetRepository::new();

            let rate_limit = RateLimitConfig::new(Arc::new(InMemoryStore::new()))
                .max_requests(2)
                .window(Duration::minutes(1));

            let action =
                ForgotPasswordAction::new(user_repo, reset_repo).with_rate_limit(rate_limit);

            // Rate limiting should still apply even for non-existent users
            let result1 = action
                .execute("nonexistent@example.com", "192.168.1.1")
                .await;
            assert!(result1.is_ok());
            assert!(result1.unwrap().is_none());

            let result2 = action
                .execute("nonexistent@example.com", "192.168.1.1")
                .await;
            assert!(result2.is_ok());

            let result3 = action
                .execute("nonexistent@example.com", "192.168.1.1")
                .await;
            assert_eq!(result3.unwrap_err(), AuthError::TooManyAttempts);
        }

        #[tokio::test]
        async fn test_forgot_password_default_rate_limit() {
            let user_repo = MockUserRepository::new();
            let reset_repo = MockPasswordResetRepository::new();

            let rate_limit = RateLimitConfig::new(Arc::new(InMemoryStore::new()));

            let action =
                ForgotPasswordAction::new(user_repo, reset_repo).with_rate_limit(rate_limit);

            // Default is 120 requests per minute
            for _ in 0..120 {
                let result = action.execute("test@example.com", "192.168.1.1").await;
                assert!(result.is_ok());
            }

            // 121st request should be rate limited
            let result = action.execute("test@example.com", "192.168.1.1").await;
            assert_eq!(result.unwrap_err(), AuthError::TooManyAttempts);
        }

        #[tokio::test]
        async fn test_forgot_password_no_rate_limit_without_config() {
            let user_repo = MockUserRepository::new();
            let reset_repo = MockPasswordResetRepository::new();

            // No rate limit configured
            let action = ForgotPasswordAction::new(user_repo, reset_repo);

            // Should not be rate limited
            for _ in 0..200 {
                let result = action.execute("test@example.com", "192.168.1.1").await;
                assert!(result.is_ok());
            }
        }
    }
}
