use chrono::{Duration, Utc};
use crate::{AccessToken, AuthError, TokenRepository, User, UserRepository};

pub struct LoginAction<U: UserRepository, T: TokenRepository> {
    user_repository: U,
    token_repository: T,
}

impl<U: UserRepository, T: TokenRepository> LoginAction<U, T> {
    pub fn new(user_repository: U, token_repository: T) -> Self {
        LoginAction { user_repository, token_repository }
    }

    pub async fn execute(&self, email: &str, password: &str) -> Result<(User, AccessToken), AuthError> {
        let user = self.user_repository.find_user_by_email(email).await?;
        if let Some(user) = user {
            if verify_password(password, &user.hashed_password)? {
                let expires_at = Utc::now() + Duration::days(7);
                let token = self.token_repository.create_token(user.id, expires_at).await?;
                return Ok((user, token));
            }
        }
        Err(AuthError::InvalidCredentials)
    }
}

fn verify_password(password: &str, hashed: &str) -> Result<bool, AuthError> {
    use argon2::{Argon2, PasswordVerifier};
    use password_hash::PasswordHash;

    let parsed_hash = PasswordHash::new(hashed).map_err(|_| AuthError::PasswordHashError)?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map(|_| true)
        .map_err(|_| AuthError::InvalidCredentials)
}

#[cfg(test)]
mod tests {
    use crate::{MockUserRepository, MockTokenRepository, User};
    use super::*;
    use rand::rngs::OsRng;
    use argon2::{Argon2, PasswordHasher};
    use password_hash::SaltString;

    #[tokio::test]
    async fn test_login_action() {
        let user_repo = MockUserRepository::new();
        let token_repo = MockTokenRepository::new();

        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        let password = "securepassword";

        let hashed = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| AuthError::PasswordHashError)
            .map(|hash| hash.to_string());

        let user = User::mock_from_credentials("user@email.com", hashed.unwrap().as_str());
        user_repo.users.lock().unwrap().push(user);

        let login = LoginAction::new(user_repo, token_repo);

        let result = login.execute("user@email.com", "securepassword").await;
        assert!(result.is_ok());
        let (user, token) = result.unwrap();
        assert_eq!(user.email, "user@email.com");
        assert!(!token.token.is_empty());
        assert_eq!(token.user_id, user.id);

        let failed_attempt = login.execute("user@email.com", "wrongpassword").await;
        assert!(failed_attempt.is_err());

        let failed_attempt = login.execute("wrong@email.com", "securepassword").await;
        assert!(failed_attempt.is_err());
    }
}
