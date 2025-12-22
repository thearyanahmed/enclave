use crate::{AccessToken, AuthError, RateLimiterRepository, TokenRepository, User, UserRepository};
use chrono::{Duration, Utc};

/// Configuration for login rate limiting behavior.
///
/// Controls how the login system handles repeated failed attempts to prevent
/// brute-force attacks while avoiding excessive lockouts for legitimate users.
///
/// # Default Values
///
/// - `max_failed_attempts`: 5
/// - `lockout_duration_minutes`: 15
///
/// # Example
///
/// ```rust
/// use enclave::actions::LoginConfig;
///
/// // Use stricter settings for sensitive applications
/// let config = LoginConfig {
///     max_failed_attempts: 3,
///     lockout_duration_minutes: 30,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct LoginConfig {
    /// Maximum number of failed login attempts before the account is locked out.
    ///
    /// Once this threshold is reached, further login attempts will be rejected
    /// with `AuthError::TooManyAttempts` until the lockout period expires.
    pub max_failed_attempts: u32,

    /// Duration in minutes that an account remains locked after exceeding
    /// the maximum failed attempts.
    ///
    /// After this period, the failed attempt counter resets and the user
    /// can attempt to log in again.
    pub lockout_duration_minutes: i64,
}

impl Default for LoginConfig {
    fn default() -> Self {
        Self {
            max_failed_attempts: 5,
            lockout_duration_minutes: 15,
        }
    }
}

pub struct LoginAction<U: UserRepository, T: TokenRepository, R: RateLimiterRepository> {
    user_repository: U,
    token_repository: T,
    rate_limiter: R,
    config: LoginConfig,
}

impl<U: UserRepository, T: TokenRepository, R: RateLimiterRepository> LoginAction<U, T, R> {
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
        // we check if account is locked out
        let since = Utc::now() - Duration::minutes(self.config.lockout_duration_minutes);
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

        if !verify_password(password, &user.hashed_password)? {
            self.rate_limiter.record_attempt(email, false, None).await?;
            return Err(AuthError::InvalidCredentials);
        }

        // Clear failed attempts on successful login
        self.rate_limiter.clear_attempts(email).await?;
        self.rate_limiter.record_attempt(email, true, None).await?;

        let expires_at = Utc::now() + Duration::days(7);
        let token = self
            .token_repository
            .create_token(user.id, expires_at)
            .await?;
        Ok((user, token))
    }
}

fn verify_password(password: &str, hashed: &str) -> Result<bool, AuthError> {
    use argon2::{Argon2, PasswordVerifier};
    use password_hash::PasswordHash;

    let parsed_hash = PasswordHash::new(hashed).map_err(|_| AuthError::PasswordHashError)?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MockRateLimiterRepository, MockTokenRepository, MockUserRepository, User};
    use argon2::{Argon2, PasswordHasher};
    use password_hash::SaltString;
    use rand::rngs::OsRng;

    fn hash_password(password: &str) -> String {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        argon2
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string()
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
