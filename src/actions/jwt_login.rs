use chrono::{Duration, Utc};

use crate::jwt::JwtService;
use crate::{AuthError, RateLimiterRepository, User, UserRepository};

use super::LoginConfig;

/// Response from a successful JWT login.
#[derive(Debug, Clone)]
pub struct JwtLoginResponse {
    /// The authenticated user.
    pub user: User,
    /// The JWT access token.
    pub token: String,
    /// Token expiration timestamp (Unix seconds).
    pub expires_at: i64,
}

/// JWT-based login action.
///
/// Uses JWT tokens instead of opaque database-backed tokens.
/// Tokens are stateless and validated via signature verification.
pub struct JwtLoginAction<U: UserRepository, R: RateLimiterRepository> {
    user_repository: U,
    rate_limiter: R,
    jwt_service: JwtService,
    config: LoginConfig,
}

impl<U: UserRepository, R: RateLimiterRepository> JwtLoginAction<U, R> {
    /// Creates a new JWT login action.
    pub fn new(user_repository: U, rate_limiter: R, jwt_service: JwtService) -> Self {
        Self::with_config(user_repository, rate_limiter, jwt_service, LoginConfig::default())
    }

    /// Creates a new JWT login action with custom rate limiting config.
    pub fn with_config(
        user_repository: U,
        rate_limiter: R,
        jwt_service: JwtService,
        config: LoginConfig,
    ) -> Self {
        Self {
            user_repository,
            rate_limiter,
            jwt_service,
            config,
        }
    }

    /// Executes the login, returning the user and JWT token on success.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "jwt_login", skip_all, err)
    )]
    pub async fn execute(
        &self,
        email: &str,
        password: &str,
    ) -> Result<JwtLoginResponse, AuthError> {
        // Check if account is locked out
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

        let token = self.jwt_service.encode(user.id)?;
        let expires_at = (Utc::now() + self.jwt_service.expiry()).timestamp();

        Ok(JwtLoginResponse {
            user,
            token,
            expires_at,
        })
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
    use crate::jwt::JwtConfig;
    use crate::{MockRateLimiterRepository, MockUserRepository, User};
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

    fn create_jwt_service() -> JwtService {
        let config = JwtConfig::new("test-secret-key-32-bytes-long!!");
        JwtService::new(config)
    }

    #[tokio::test]
    async fn test_jwt_login_success() {
        let user_repo = MockUserRepository::new();
        let rate_limiter = MockRateLimiterRepository::new();
        let jwt_service = create_jwt_service();

        let user = User::mock_from_credentials("user@email.com", &hash_password("securepassword"));
        user_repo.users.lock().unwrap().push(user);

        let login = JwtLoginAction::new(user_repo, rate_limiter, jwt_service.clone());

        let result = login.execute("user@email.com", "securepassword").await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.user.email, "user@email.com");
        assert!(!response.token.is_empty());

        // Verify token is valid
        let claims = jwt_service.decode(&response.token).unwrap();
        assert_eq!(claims.user_id().unwrap(), response.user.id);
    }

    #[tokio::test]
    async fn test_jwt_login_invalid_credentials() {
        let user_repo = MockUserRepository::new();
        let rate_limiter = MockRateLimiterRepository::new();
        let jwt_service = create_jwt_service();

        let user = User::mock_from_credentials("user@email.com", &hash_password("securepassword"));
        user_repo.users.lock().unwrap().push(user);

        let login = JwtLoginAction::new(user_repo, rate_limiter, jwt_service);

        let result = login.execute("user@email.com", "wrongpassword").await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::InvalidCredentials);
    }

    #[tokio::test]
    async fn test_jwt_login_too_many_attempts() {
        let user_repo = MockUserRepository::new();
        let rate_limiter = MockRateLimiterRepository::new();
        let jwt_service = create_jwt_service();

        let user = User::mock_from_credentials("user@email.com", &hash_password("securepassword"));
        user_repo.users.lock().unwrap().push(user);

        let login = JwtLoginAction::new(user_repo, rate_limiter, jwt_service);

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
