use crate::validators::validate_password;
use crate::{AuthError, PasswordResetRepository, UserRepository};
use argon2::{Argon2, PasswordHasher};
use chrono::Utc;
use password_hash::SaltString;
use rand::rngs::OsRng;

pub struct ResetPasswordAction<U: UserRepository, P: PasswordResetRepository> {
    user_repository: U,
    reset_repository: P,
}

impl<U: UserRepository, P: PasswordResetRepository> ResetPasswordAction<U, P> {
    pub fn new(user_repository: U, reset_repository: P) -> Self {
        ResetPasswordAction {
            user_repository,
            reset_repository,
        }
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "reset_password", skip_all, err)
    )]
    pub async fn execute(&self, token: &str, new_password: &str) -> Result<(), AuthError> {
        validate_password(new_password)?;

        let reset_token = self.reset_repository.find_reset_token(token).await?;

        match reset_token {
            Some(reset_token) => {
                if reset_token.expires_at < Utc::now() {
                    self.reset_repository.delete_reset_token(token).await?;
                    return Err(AuthError::TokenExpired);
                }

                let hashed = hash_password(new_password)?;
                self.user_repository
                    .update_password(reset_token.user_id, &hashed)
                    .await?;
                self.reset_repository.delete_reset_token(token).await?;

                Ok(())
            }
            None => Err(AuthError::TokenInvalid),
        }
    }
}

fn hash_password(password: &str) -> Result<String, AuthError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| AuthError::PasswordHashError)
        .map(|hash| hash.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validators::ValidationError;
    use crate::{MockPasswordResetRepository, MockUserRepository, User};
    use chrono::Duration;

    #[tokio::test]
    async fn test_reset_password_success() {
        let user_repo = MockUserRepository::new();
        let reset_repo = MockPasswordResetRepository::new();

        let user = User::mock_from_email("user@example.com");
        let user_id = user.id;
        user_repo.users.lock().unwrap().push(user);

        let expires_at = Utc::now() + Duration::hours(1);
        let token = reset_repo
            .create_reset_token(user_id, expires_at)
            .await
            .unwrap();

        let action = ResetPasswordAction::new(user_repo, reset_repo);
        let result = action.execute(&token.token, "newpassword123").await;

        assert!(result.is_ok());

        // Token should be deleted
        let found = action
            .reset_repository
            .find_reset_token(&token.token)
            .await
            .unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_reset_password_invalid_token() {
        let user_repo = MockUserRepository::new();
        let reset_repo = MockPasswordResetRepository::new();

        let action = ResetPasswordAction::new(user_repo, reset_repo);
        let result = action.execute("invalid_token", "newpassword123").await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::TokenInvalid);
    }

    #[tokio::test]
    async fn test_reset_password_expired_token() {
        let user_repo = MockUserRepository::new();
        let reset_repo = MockPasswordResetRepository::new();

        let user = User::mock_from_email("user@example.com");
        let user_id = user.id;
        user_repo.users.lock().unwrap().push(user);

        let expires_at = Utc::now() - Duration::hours(1); // Already expired
        let token = reset_repo
            .create_reset_token(user_id, expires_at)
            .await
            .unwrap();

        let action = ResetPasswordAction::new(user_repo, reset_repo);
        let result = action.execute(&token.token, "newpassword123").await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::TokenExpired);
    }

    #[tokio::test]
    async fn test_reset_password_invalid_password() {
        let user_repo = MockUserRepository::new();
        let reset_repo = MockPasswordResetRepository::new();

        let action = ResetPasswordAction::new(user_repo, reset_repo);
        let result = action.execute("sometoken", "short").await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            AuthError::Validation(ValidationError::PasswordTooShort)
        );
    }
}
