use crate::{AuthError, PasswordResetRepository, PasswordResetToken, UserRepository};
use chrono::{Duration, Utc};

#[cfg(feature = "rate_limit")]
use crate::rate_limit::RateLimitStore;
#[cfg(feature = "rate_limit")]
use std::sync::Arc;

/// Configuration for password reset behavior.
///
/// # Example
///
/// ```rust
/// use enclave::actions::ForgotPasswordConfig;
/// use chrono::Duration;
///
/// // Default: 120 requests per minute
/// let config = ForgotPasswordConfig::default();
///
/// // Custom: 60 requests per hour
/// let config = ForgotPasswordConfig {
///     password_reset_expiry: Duration::hours(1),
///     rate_limit_requests: 60,
///     rate_limit_window: Duration::hours(1),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct ForgotPasswordConfig {
    /// How long password reset tokens remain valid.
    ///
    /// Default: 1 hour
    pub password_reset_expiry: Duration,

    /// Maximum number of password reset requests allowed per window.
    ///
    /// Default: 120
    pub rate_limit_requests: u32,

    /// Time window for rate limiting.
    ///
    /// Default: 1 minute
    pub rate_limit_window: Duration,
}

impl Default for ForgotPasswordConfig {
    fn default() -> Self {
        Self {
            password_reset_expiry: Duration::hours(1),
            rate_limit_requests: 120,
            rate_limit_window: Duration::minutes(1),
        }
    }
}

impl ForgotPasswordConfig {
    /// Creates config from a `TokenConfig`.
    pub fn from_token_config(tokens: &crate::config::TokenConfig) -> Self {
        Self {
            password_reset_expiry: tokens.password_reset_expiry,
            ..Default::default()
        }
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
    rate_limit_store: Option<Arc<dyn RateLimitStore>>,
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
            rate_limit_store: None,
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
    /// Adds a rate limit store to enable rate limiting.
    ///
    /// Rate limiting uses the config values:
    /// - `rate_limit_requests`: max requests allowed (default: 120)
    /// - `rate_limit_window`: time window (default: 1 minute)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use enclave::rate_limit::InMemoryStore;
    /// use std::sync::Arc;
    ///
    /// let store = Arc::new(InMemoryStore::new());
    /// let action = ForgotPasswordAction::new(user_repo, reset_repo)
    ///     .with_rate_limit_store(store);
    /// ```
    #[must_use]
    pub fn with_rate_limit_store(mut self, store: Arc<dyn RateLimitStore>) -> Self {
        self.rate_limit_store = Some(store);
        self
    }

    /// Sets the rate limit (requests per window).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use chrono::Duration;
    ///
    /// // 60 requests per hour
    /// let action = ForgotPasswordAction::new(user_repo, reset_repo)
    ///     .with_rate_limit_store(store)
    ///     .rate_limit(60, Duration::hours(1));
    /// ```
    #[must_use]
    pub fn rate_limit(mut self, requests: u32, window: Duration) -> Self {
        self.config.rate_limit_requests = requests;
        self.config.rate_limit_window = window;
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
    /// # Rate Limiting
    ///
    /// When a rate limit store is configured, requests are limited to
    /// `config.rate_limit_requests` per `config.rate_limit_window` (default: 120/minute per IP).
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
        if let Some(ref store) = self.rate_limit_store {
            let window_secs = u64::try_from(self.config.rate_limit_window.num_seconds().max(1))
                .unwrap_or(60);
            let key = format!("forgot_password:{rate_limit_key}");
            let info = store.increment(&key, window_secs).await?;

            if info.attempts > self.config.rate_limit_requests {
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

            let store = Arc::new(InMemoryStore::new());
            let action = ForgotPasswordAction::new(user_repo, reset_repo)
                .with_rate_limit_store(store)
                .rate_limit(2, Duration::minutes(1));

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

            let store = Arc::new(InMemoryStore::new());
            let action = ForgotPasswordAction::new(user_repo, reset_repo)
                .with_rate_limit_store(store)
                .rate_limit(1, Duration::minutes(1));

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

            let store = Arc::new(InMemoryStore::new());
            let action = ForgotPasswordAction::new(user_repo, reset_repo)
                .with_rate_limit_store(store)
                .rate_limit(2, Duration::minutes(1));

            // Rate limiting should still apply even for non-existent users
            // (prevents user enumeration via rate limit behavior)
            let result1 = action.execute("nonexistent@example.com", "192.168.1.1").await;
            assert!(result1.is_ok());
            assert!(result1.unwrap().is_none());

            let result2 = action.execute("nonexistent@example.com", "192.168.1.1").await;
            assert!(result2.is_ok());

            let result3 = action.execute("nonexistent@example.com", "192.168.1.1").await;
            assert_eq!(result3.unwrap_err(), AuthError::TooManyAttempts);
        }

        #[tokio::test]
        async fn test_forgot_password_default_rate_limit() {
            let user_repo = MockUserRepository::new();
            let reset_repo = MockPasswordResetRepository::new();

            let store = Arc::new(InMemoryStore::new());
            let action = ForgotPasswordAction::new(user_repo, reset_repo)
                .with_rate_limit_store(store);

            // Default is 120 requests per minute - should not be rate limited
            for _ in 0..120 {
                let result = action.execute("test@example.com", "192.168.1.1").await;
                assert!(result.is_ok());
            }

            // 121st request should be rate limited
            let result = action.execute("test@example.com", "192.168.1.1").await;
            assert_eq!(result.unwrap_err(), AuthError::TooManyAttempts);
        }

        #[tokio::test]
        async fn test_forgot_password_no_rate_limit_without_store() {
            let user_repo = MockUserRepository::new();
            let reset_repo = MockPasswordResetRepository::new();

            // No rate limit store configured
            let action = ForgotPasswordAction::new(user_repo, reset_repo);

            // Should not be rate limited even after many requests
            for _ in 0..200 {
                let result = action.execute("test@example.com", "192.168.1.1").await;
                assert!(result.is_ok());
            }
        }
    }
}
