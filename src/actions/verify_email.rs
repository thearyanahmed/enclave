use chrono::Utc;
use crate::{AuthError, EmailVerificationRepository, UserRepository};

pub struct VerifyEmailAction<U: UserRepository, E: EmailVerificationRepository> {
    user_repository: U,
    verification_repository: E,
}

impl<U: UserRepository, E: EmailVerificationRepository> VerifyEmailAction<U, E> {
    pub fn new(user_repository: U, verification_repository: E) -> Self {
        Self { user_repository, verification_repository }
    }

    pub async fn execute(&self, token: &str) -> Result<(), AuthError> {
        let verification_token = self.verification_repository.find_verification_token(token).await?;

        match verification_token {
            Some(verification_token) => {
                if verification_token.expires_at < Utc::now() {
                    self.verification_repository.delete_verification_token(token).await?;
                    return Err(AuthError::TokenExpired);
                }

                self.user_repository.verify_email(verification_token.user_id).await?;
                self.verification_repository.delete_verification_token(token).await?;

                Ok(())
            }
            None => Err(AuthError::TokenInvalid),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MockUserRepository, MockEmailVerificationRepository, User};
    use chrono::Duration;

    #[tokio::test]
    async fn test_verify_email_success() {
        let user_repo = MockUserRepository::new();
        let verification_repo = MockEmailVerificationRepository::new();

        let user = User::mock_from_email("user@example.com");
        let user_id = user.id;
        user_repo.users.lock().unwrap().push(user);

        let expires_at = Utc::now() + Duration::hours(24);
        let token = verification_repo.create_verification_token(user_id, expires_at).await.unwrap();

        let action = VerifyEmailAction::new(user_repo, verification_repo);
        let result = action.execute(&token.token).await;

        assert!(result.is_ok());

        // User should be verified
        let user = action.user_repository.find_user_by_id(user_id).await.unwrap().unwrap();
        assert!(user.email_verified_at.is_some());

        // Token should be deleted
        let found = action.verification_repository.find_verification_token(&token.token).await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_verify_email_invalid_token() {
        let user_repo = MockUserRepository::new();
        let verification_repo = MockEmailVerificationRepository::new();

        let action = VerifyEmailAction::new(user_repo, verification_repo);
        let result = action.execute("invalid_token").await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::TokenInvalid);
    }

    #[tokio::test]
    async fn test_verify_email_expired_token() {
        let user_repo = MockUserRepository::new();
        let verification_repo = MockEmailVerificationRepository::new();

        let user = User::mock_from_email("user@example.com");
        let user_id = user.id;
        user_repo.users.lock().unwrap().push(user);

        let expires_at = Utc::now() - Duration::hours(1); // Already expired
        let token = verification_repo.create_verification_token(user_id, expires_at).await.unwrap();

        let action = VerifyEmailAction::new(user_repo, verification_repo);
        let result = action.execute(&token.token).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::TokenExpired);
    }
}
