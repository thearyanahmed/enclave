use chrono::{Duration, Utc};
use crate::{AccessToken, AuthError, RateLimiterRepository, TokenRepository, User, UserRepository};

const MAX_FAILED_ATTEMPTS: u32 = 5;
const LOCKOUT_DURATION_MINUTES: i64 = 15;

pub struct LoginAction<U: UserRepository, T: TokenRepository, R: RateLimiterRepository> {
    user_repository: U,
    token_repository: T,
    rate_limiter: R,
}

impl<U: UserRepository, T: TokenRepository, R: RateLimiterRepository> LoginAction<U, T, R> {
    pub fn new(user_repository: U, token_repository: T, rate_limiter: R) -> Self {
        Self { user_repository, token_repository, rate_limiter }
    }

    pub async fn execute(&self, email: &str, password: &str) -> Result<(User, AccessToken), AuthError> {
        // we check if account is locked out
        let since = Utc::now() - Duration::minutes(LOCKOUT_DURATION_MINUTES);
        let failed_attempts = self.rate_limiter.get_recent_failed_attempts(email, since).await?;
        if failed_attempts >= MAX_FAILED_ATTEMPTS {
            return Err(AuthError::TooManyAttempts);
        }

        let user = self.user_repository.find_user_by_email(email).await?;
        if let Some(user) = user {
            if verify_password(password, &user.hashed_password)? {
                // Clear failed attempts on successful login
                self.rate_limiter.clear_attempts(email).await?;
                self.rate_limiter.record_attempt(email, true, None).await?;

                let expires_at = Utc::now() + Duration::days(7);
                let token = self.token_repository.create_token(user.id, expires_at).await?;
                return Ok((user, token));
            }
        }

        // record failed attempt
        self.rate_limiter.record_attempt(email, false, None).await?;
        Err(AuthError::InvalidCredentials)
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
    use crate::{MockUserRepository, MockTokenRepository, MockRateLimiterRepository, User};
    use super::*;
    use rand::rngs::OsRng;
    use argon2::{Argon2, PasswordHasher};
    use password_hash::SaltString;

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
