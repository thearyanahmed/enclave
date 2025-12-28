use chrono::{Duration, Utc};

#[cfg(feature = "rate_limit")]
use super::forgot_password::RateLimitConfig;
use crate::{AuthError, EmailVerificationRepository, EmailVerificationToken, UserRepository};

/// Configuration for email verification behavior.
#[derive(Debug, Clone)]
pub struct SendVerificationConfig {
    /// How long email verification tokens remain valid.
    ///
    /// Default: 24 hours
    pub email_verification_expiry: Duration,
}

impl Default for SendVerificationConfig {
    fn default() -> Self {
        Self {
            email_verification_expiry: Duration::hours(24),
        }
    }
}

impl SendVerificationConfig {
    /// Creates config from a `TokenConfig`.
    pub fn from_token_config(tokens: &crate::config::TokenConfig) -> Self {
        Self {
            email_verification_expiry: tokens.email_verification_expiry,
        }
    }
}

pub struct SendVerificationAction<U: UserRepository, E: EmailVerificationRepository> {
    user_repository: U,
    verification_repository: E,
    #[cfg(feature = "rate_limit")]
    rate_limit: Option<RateLimitConfig>,
    config: SendVerificationConfig,
}

impl<U: UserRepository, E: EmailVerificationRepository> SendVerificationAction<U, E> {
    pub fn new(user_repository: U, verification_repository: E) -> Self {
        Self::with_config(
            user_repository,
            verification_repository,
            SendVerificationConfig::default(),
        )
    }

    pub fn with_config(
        user_repository: U,
        verification_repository: E,
        config: SendVerificationConfig,
    ) -> Self {
        SendVerificationAction {
            user_repository,
            verification_repository,
            #[cfg(feature = "rate_limit")]
            rate_limit: None,
            config,
        }
    }

    /// Sets the configuration.
    #[must_use]
    pub fn config(mut self, config: SendVerificationConfig) -> Self {
        self.config = config;
        self
    }
}

#[cfg(feature = "rate_limit")]
impl<U: UserRepository, E: EmailVerificationRepository> SendVerificationAction<U, E> {
    /// Adds rate limiting to the send verification action.
    #[must_use]
    pub fn with_rate_limit(mut self, config: RateLimitConfig) -> Self {
        self.rate_limit = Some(config);
        self
    }

    /// Sends a verification email to the user.
    ///
    /// Rate limiting is applied by the provided key (typically client IP).
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "send_verification", skip_all, err)
    )]
    pub async fn execute(
        &self,
        user_id: i32,
        rate_limit_key: &str,
    ) -> Result<EmailVerificationToken, AuthError> {
        if let Some(ref rate_limit) = self.rate_limit {
            let window_secs = u64::try_from(rate_limit.window.num_seconds().max(1)).unwrap_or(60);
            let key = format!("send_verification:{rate_limit_key}");
            let info = rate_limit.store.increment(&key, window_secs).await?;

            if info.attempts > rate_limit.max_requests {
                return Err(AuthError::TooManyAttempts);
            }
        }

        self.execute_internal(user_id).await
    }
}

#[cfg(not(feature = "rate_limit"))]
impl<U: UserRepository, E: EmailVerificationRepository> SendVerificationAction<U, E> {
    /// Sends a verification email to the user.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "send_verification", skip_all, err)
    )]
    pub async fn execute(&self, user_id: i32) -> Result<EmailVerificationToken, AuthError> {
        self.execute_internal(user_id).await
    }
}

impl<U: UserRepository, E: EmailVerificationRepository> SendVerificationAction<U, E> {
    async fn execute_internal(&self, user_id: i32) -> Result<EmailVerificationToken, AuthError> {
        let user = self.user_repository.find_user_by_id(user_id).await?;

        match user {
            Some(user) => {
                if user.email_verified_at.is_some() {
                    return Err(AuthError::EmailAlreadyVerified);
                }

                let expires_at = Utc::now() + self.config.email_verification_expiry;
                let token = self
                    .verification_repository
                    .create_verification_token(user.id, expires_at)
                    .await?;

                log::info!(
                    target: "enclave_auth",
                    "msg=\"verification sent\", user_id={user_id}"
                );

                Ok(token)
            }
            None => Err(AuthError::UserNotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthUser, MockEmailVerificationRepository, MockUserRepository};

    #[cfg(not(feature = "rate_limit"))]
    #[tokio::test]
    async fn test_send_verification_creates_token() {
        let user_repo = MockUserRepository::new();
        let verification_repo = MockEmailVerificationRepository::new();

        let user = AuthUser::mock_from_email("user@example.com");
        let user_id = user.id;
        user_repo.users.lock().unwrap().push(user);

        let action = SendVerificationAction::new(user_repo, verification_repo);
        let result = action.execute(user_id).await;

        assert!(result.is_ok());
        let token = result.unwrap();
        assert_eq!(token.user_id, user_id);
        assert!(!token.token.is_empty());
    }

    #[cfg(not(feature = "rate_limit"))]
    #[tokio::test]
    async fn test_send_verification_user_not_found() {
        let user_repo = MockUserRepository::new();
        let verification_repo = MockEmailVerificationRepository::new();

        let action = SendVerificationAction::new(user_repo, verification_repo);
        let result = action.execute(999).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::UserNotFound);
    }

    #[cfg(not(feature = "rate_limit"))]
    #[tokio::test]
    async fn test_send_verification_already_verified() {
        let user_repo = MockUserRepository::new();
        let verification_repo = MockEmailVerificationRepository::new();

        let mut user = AuthUser::mock_from_email("user@example.com");
        user.email_verified_at = Some(Utc::now());
        let user_id = user.id;
        user_repo.users.lock().unwrap().push(user);

        let action = SendVerificationAction::new(user_repo, verification_repo);
        let result = action.execute(user_id).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::EmailAlreadyVerified);
    }

    #[cfg(feature = "rate_limit")]
    mod rate_limit_tests {
        use std::sync::Arc;

        use super::*;
        use crate::rate_limit::InMemoryStore;

        #[tokio::test]
        async fn test_send_verification_creates_token() {
            let user_repo = MockUserRepository::new();
            let verification_repo = MockEmailVerificationRepository::new();

            let user = AuthUser::mock_from_email("user@example.com");
            let user_id = user.id;
            user_repo.users.lock().unwrap().push(user);

            let action = SendVerificationAction::new(user_repo, verification_repo);
            let result = action.execute(user_id, "127.0.0.1").await;

            assert!(result.is_ok());
            let token = result.unwrap();
            assert_eq!(token.user_id, user_id);
            assert!(!token.token.is_empty());
        }

        #[tokio::test]
        async fn test_send_verification_user_not_found() {
            let user_repo = MockUserRepository::new();
            let verification_repo = MockEmailVerificationRepository::new();

            let action = SendVerificationAction::new(user_repo, verification_repo);
            let result = action.execute(999, "127.0.0.1").await;

            assert!(result.is_err());
            assert_eq!(result.unwrap_err(), AuthError::UserNotFound);
        }

        #[tokio::test]
        async fn test_send_verification_already_verified() {
            let user_repo = MockUserRepository::new();
            let verification_repo = MockEmailVerificationRepository::new();

            let mut user = AuthUser::mock_from_email("user@example.com");
            user.email_verified_at = Some(Utc::now());
            let user_id = user.id;
            user_repo.users.lock().unwrap().push(user);

            let action = SendVerificationAction::new(user_repo, verification_repo);
            let result = action.execute(user_id, "127.0.0.1").await;

            assert!(result.is_err());
            assert_eq!(result.unwrap_err(), AuthError::EmailAlreadyVerified);
        }

        #[tokio::test]
        async fn test_send_verification_rate_limited() {
            let user_repo = MockUserRepository::new();
            let verification_repo = MockEmailVerificationRepository::new();

            let user = AuthUser::mock_from_email("user@example.com");
            let user_id = user.id;
            user_repo.users.lock().unwrap().push(user);

            let rate_limit = RateLimitConfig::new(Arc::new(InMemoryStore::new()))
                .max_requests(2)
                .window(Duration::minutes(1));

            let action = SendVerificationAction::new(user_repo, verification_repo)
                .with_rate_limit(rate_limit);

            // First two requests should succeed
            let result1 = action.execute(user_id, "192.168.1.1").await;
            assert!(result1.is_ok());

            let result2 = action.execute(user_id, "192.168.1.1").await;
            assert!(result2.is_ok());

            // Third request should be rate limited
            let result3 = action.execute(user_id, "192.168.1.1").await;
            assert!(result3.is_err());
            assert_eq!(result3.unwrap_err(), AuthError::TooManyAttempts);
        }

        #[tokio::test]
        async fn test_send_verification_rate_limit_different_ips() {
            let user_repo = MockUserRepository::new();
            let verification_repo = MockEmailVerificationRepository::new();

            let user = AuthUser::mock_from_email("user@example.com");
            let user_id = user.id;
            user_repo.users.lock().unwrap().push(user);

            let rate_limit = RateLimitConfig::new(Arc::new(InMemoryStore::new()))
                .max_requests(1)
                .window(Duration::minutes(1));

            let action = SendVerificationAction::new(user_repo, verification_repo)
                .with_rate_limit(rate_limit);

            // First IP uses its quota
            let result1 = action.execute(user_id, "192.168.1.1").await;
            assert!(result1.is_ok());

            let result2 = action.execute(user_id, "192.168.1.1").await;
            assert_eq!(result2.unwrap_err(), AuthError::TooManyAttempts);

            // Second IP should still work
            let result3 = action.execute(user_id, "192.168.1.2").await;
            assert!(result3.is_ok());
        }
    }
}
