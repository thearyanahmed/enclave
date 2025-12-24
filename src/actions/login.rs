use crate::config::{RateLimitConfig, TokenConfig};
use crate::crypto::{Argon2Hasher, PasswordHasher};
use crate::{AccessToken, AuthError, RateLimiterRepository, TokenRepository, User, UserRepository};
use chrono::{Duration, Utc};

/// Configuration for login behavior including rate limiting and token expiry.
///
/// Controls how the login system handles repeated failed attempts to prevent
/// brute-force attacks while avoiding excessive lockouts for legitimate users.
///
/// # Default Values
///
/// - `max_failed_attempts`: 5
/// - `lockout_duration`: 15 minutes
/// - `access_token_expiry`: 7 days
///
/// # Example
///
/// ```rust
/// use enclave::actions::LoginConfig;
/// use chrono::Duration;
///
/// // Use stricter settings for sensitive applications
/// let config = LoginConfig {
///     max_failed_attempts: 3,
///     lockout_duration: Duration::minutes(30),
///     access_token_expiry: Duration::hours(1),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct LoginConfig {
    /// Maximum number of failed login attempts before the account is locked out.
    ///
    /// Once this threshold is reached, further login attempts will be rejected
    /// with `AuthError::TooManyAttempts` until the lockout period expires.
    pub max_failed_attempts: u32,

    /// Duration that an account remains locked after exceeding the maximum failed attempts.
    ///
    /// After this period, the failed attempt counter resets and the user
    /// can attempt to log in again.
    pub lockout_duration: Duration,

    /// How long access tokens remain valid after creation.
    ///
    /// Default: 7 days
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
    /// Creates a `LoginConfig` from `RateLimitConfig` and `TokenConfig`.
    ///
    /// This is useful when you have an `AuthConfig` and want to create
    /// a `LoginConfig` from its components.
    pub fn from_configs(rate_limit: &RateLimitConfig, tokens: &TokenConfig) -> Self {
        Self {
            max_failed_attempts: rate_limit.max_failed_attempts,
            lockout_duration: rate_limit.lockout_duration,
            access_token_expiry: tokens.access_token_expiry,
        }
    }

    /// Returns the lockout duration in minutes.
    ///
    /// Convenience method for backwards compatibility.
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
    pub fn new(user_repository: U, token_repository: T, rate_limiter: R) -> Self {
        Self::with_config(
            user_repository,
            token_repository,
            rate_limiter,
            LoginConfig::default(),
        )
    }

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

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "login", skip_all, err)
    )]
    pub async fn execute(
        &self,
        email: &str,
        password: &str,
    ) -> Result<(User, AccessToken), AuthError> {
        // Check if account is locked out
        let since = Utc::now() - self.config.lockout_duration;
        let failed_attempts = self
            .rate_limiter
            .get_recent_failed_attempts(email, since)
            .await?;
        if failed_attempts >= self.config.max_failed_attempts {
            return Err(AuthError::TooManyAttempts);
        }

        let user = match self.user_repository.find_user_by_email(email).await? {
            Some(u) => u,
            None => {
                self.rate_limiter.record_attempt(email, false, None).await?;
                return Err(AuthError::InvalidCredentials);
            }
        };

        if !self.hasher.verify(password, &user.hashed_password)? {
            self.rate_limiter.record_attempt(email, false, None).await?;
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
        Ok((user, token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Argon2Hasher;
    use crate::{MockRateLimiterRepository, MockTokenRepository, MockUserRepository, User};

    fn hash_password(password: &str) -> String {
        Argon2Hasher::default().hash(password).unwrap()
    }

    #[tokio::test]
    async fn test_login_success() {
        let user_repo = MockUserRepository::new();
        let token_repo = MockTokenRepository::new();
        let rate_limiter = MockRateLimiterRepository::new();

        let user = User::mock_from_credentials("user@email.com", &hash_password("securepassword"));
        user_repo.users.lock().unwrap().push(user);

        let login = LoginAction::new(user_repo, token_repo, rate_limiter);

        let result = login.execute("user@email.com", "securepassword").await;
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

        let user = User::mock_from_credentials("user@email.com", &hash_password("securepassword"));
        user_repo.users.lock().unwrap().push(user);

        let login = LoginAction::new(user_repo, token_repo, rate_limiter);

        let result = login.execute("user@email.com", "wrongpassword").await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::InvalidCredentials);
    }

    #[tokio::test]
    async fn test_login_too_many_attempts() {
        let user_repo = MockUserRepository::new();
        let token_repo = MockTokenRepository::new();
        let rate_limiter = MockRateLimiterRepository::new();

        let user = User::mock_from_credentials("user@email.com", &hash_password("securepassword"));
        user_repo.users.lock().unwrap().push(user);

        let login = LoginAction::new(user_repo, token_repo, rate_limiter);

        // Make 5 failed attempts
        for _ in 0..5 {
            let _ = login.execute("user@email.com", "wrongpassword").await;
        }

        // 6th attempt should be blocked
        let result = login.execute("user@email.com", "securepassword").await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::TooManyAttempts);
    }
}
