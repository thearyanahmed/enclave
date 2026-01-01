use chrono::{Duration, Utc};

use crate::config::{RateLimitConfig, TokenConfig};
use crate::crypto::{Argon2Hasher, PasswordHasher};
use crate::events::{AuthEvent, dispatch};
use crate::{
    AccessToken, AuthError, AuthUser, RateLimiterRepository, SecretString, TokenRepository,
    UserRepository,
};

#[derive(Debug, Clone)]
pub struct LoginConfig {
    pub max_failed_attempts: u32,
    pub lockout_duration: Duration,
    pub access_token_expiry: Duration,
}

impl Default for LoginConfig {
    fn default() -> Self {
        Self {
            max_failed_attempts: 5,
            lockout_duration: Duration::minutes(15),
            access_token_expiry: Duration::days(7),
        }
    }
}

impl LoginConfig {
    pub fn from_configs(rate_limit: &RateLimitConfig, tokens: &TokenConfig) -> Self {
        Self {
            max_failed_attempts: rate_limit.max_failed_attempts,
            lockout_duration: rate_limit.lockout_duration,
            access_token_expiry: tokens.access_token_expiry,
        }
    }

    #[deprecated(note = "Use lockout_duration directly")]
    pub fn lockout_duration_minutes(&self) -> i64 {
        self.lockout_duration.num_minutes()
    }
}

pub struct LoginAction<U, T, R, H = Argon2Hasher>
where
    U: UserRepository,
    T: TokenRepository,
    R: RateLimiterRepository,
{
    user_repository: U,
    token_repository: T,
    rate_limiter: R,
    config: LoginConfig,
    hasher: H,
}

impl<U: UserRepository, T: TokenRepository, R: RateLimiterRepository>
    LoginAction<U, T, R, Argon2Hasher>
{
    /// Creates a new `LoginAction` with default configuration and Argon2 hasher.
    ///
    /// Default config: 5 failed attempts, 15 minute lockout, 7 day token expiry.
    /// For custom settings, use [`with_config`].
    ///
    /// [`with_config`]: Self::with_config
    pub fn new(user_repository: U, token_repository: T, rate_limiter: R) -> Self {
        Self::with_config(
            user_repository,
            token_repository,
            rate_limiter,
            LoginConfig::default(),
        )
    }

    /// Creates a new `LoginAction` with custom configuration.
    ///
    /// Use [`LoginConfig::from_configs`] to build from `RateLimitConfig` and `TokenConfig`.
    ///
    /// [`LoginConfig::from_configs`]: LoginConfig::from_configs
    pub fn with_config(
        user_repository: U,
        token_repository: T,
        rate_limiter: R,
        config: LoginConfig,
    ) -> Self {
        LoginAction {
            user_repository,
            token_repository,
            rate_limiter,
            config,
            hasher: Argon2Hasher::default(),
        }
    }
}

impl<U: UserRepository, T: TokenRepository, R: RateLimiterRepository, H: PasswordHasher>
    LoginAction<U, T, R, H>
{
    /// Creates a new `LoginAction` with a custom password hasher.
    ///
    /// Use this for testing with mock hashers or alternative algorithms.
    pub fn with_hasher(
        user_repository: U,
        token_repository: T,
        rate_limiter: R,
        config: LoginConfig,
        hasher: H,
    ) -> Self {
        LoginAction {
            user_repository,
            token_repository,
            rate_limiter,
            config,
            hasher,
        }
    }

    /// Authenticates a user with email and password.
    ///
    /// Failed attempts are tracked for rate limiting. After `max_failed_attempts`,
    /// the account is locked for `lockout_duration`.
    ///
    /// # Returns
    ///
    /// - `Ok((user, token))` - valid credentials, returns user and access token
    /// - `Err(AuthError::InvalidCredentials)` - wrong email or password
    /// - `Err(AuthError::TooManyAttempts)` - account locked due to failed attempts
    /// - `Err(_)` - database or other errors
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "login", skip_all, err)
    )]
    pub async fn execute(
        &self,
        email: &str,
        password: &SecretString,
    ) -> Result<(AuthUser, AccessToken), AuthError> {
        // Check if account is locked out
        let since = Utc::now() - self.config.lockout_duration;
        let failed_attempts = self
            .rate_limiter
            .get_recent_failed_attempts(email, since)
            .await?;
        if failed_attempts >= self.config.max_failed_attempts {
            dispatch(AuthEvent::LoginFailed {
                email: email.to_owned(),
                reason: "too many attempts".to_owned(),
                at: Utc::now(),
            })
            .await;
            return Err(AuthError::TooManyAttempts);
        }

        let user = match self.user_repository.find_user_by_email(email).await? {
            Some(u) => u,
            None => {
                self.rate_limiter.record_attempt(email, false, None).await?;
                dispatch(AuthEvent::LoginFailed {
                    email: email.to_owned(),
                    reason: "invalid credentials".to_owned(),
                    at: Utc::now(),
                })
                .await;
                return Err(AuthError::InvalidCredentials);
            }
        };

        if !self
            .hasher
            .verify(password.expose_secret(), &user.hashed_password)?
        {
            self.rate_limiter.record_attempt(email, false, None).await?;
            dispatch(AuthEvent::LoginFailed {
                email: email.to_owned(),
                reason: "invalid credentials".to_owned(),
                at: Utc::now(),
            })
            .await;
            return Err(AuthError::InvalidCredentials);
        }

        // Clear failed attempts on successful login
        self.rate_limiter.clear_attempts(email).await?;
        self.rate_limiter.record_attempt(email, true, None).await?;

        let expires_at = Utc::now() + self.config.access_token_expiry;
        let token = self
            .token_repository
            .create_token(user.id, expires_at)
            .await?;

        dispatch(AuthEvent::LoginSuccess {
            user_id: user.id,
            email: user.email.clone(),
            at: Utc::now(),
        })
        .await;

        log::info!(
            target: "enclave_auth",
            "msg=\"login success\", user_id={}",
            user.id
        );

        Ok((user, token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Argon2Hasher;
    use crate::{
        AuthUser, MockRateLimiterRepository, MockTokenRepository, MockUserRepository, SecretString,
    };

    fn hash_password(password: &str) -> String {
        Argon2Hasher::default().hash(password).unwrap()
    }

    #[tokio::test]
    async fn test_login_success() {
        let user_repo = MockUserRepository::new();
        let token_repo = MockTokenRepository::new();
        let rate_limiter = MockRateLimiterRepository::new();

        let user =
            AuthUser::mock_from_credentials("user@email.com", &hash_password("securepassword"));
        user_repo.users.lock().unwrap().push(user);

        let login = LoginAction::new(user_repo, token_repo, rate_limiter);

        let password = SecretString::new("securepassword");
        let result = login.execute("user@email.com", &password).await;
        assert!(result.is_ok());
        let (user, token) = result.unwrap();
        assert_eq!(user.email, "user@email.com");
        assert!(!token.token.is_empty());
        assert_eq!(token.user_id, user.id);
    }

    #[tokio::test]
    async fn test_login_invalid_credentials() {
        let user_repo = MockUserRepository::new();
        let token_repo = MockTokenRepository::new();
        let rate_limiter = MockRateLimiterRepository::new();

        let user =
            AuthUser::mock_from_credentials("user@email.com", &hash_password("securepassword"));
        user_repo.users.lock().unwrap().push(user);

        let login = LoginAction::new(user_repo, token_repo, rate_limiter);

        let password = SecretString::new("wrongpassword");
        let result = login.execute("user@email.com", &password).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::InvalidCredentials);
    }

    #[tokio::test]
    async fn test_login_too_many_attempts() {
        let user_repo = MockUserRepository::new();
        let token_repo = MockTokenRepository::new();
        let rate_limiter = MockRateLimiterRepository::new();

        let user =
            AuthUser::mock_from_credentials("user@email.com", &hash_password("securepassword"));
        user_repo.users.lock().unwrap().push(user);

        let login = LoginAction::new(user_repo, token_repo, rate_limiter);

        // Make 5 failed attempts
        let wrong_password = SecretString::new("wrongpassword");
        for _ in 0..5 {
            let _ = login.execute("user@email.com", &wrong_password).await;
        }

        // 6th attempt should be blocked
        let correct_password = SecretString::new("securepassword");
        let result = login.execute("user@email.com", &correct_password).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::TooManyAttempts);
    }
}
