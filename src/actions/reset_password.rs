use crate::SecretString;
use crate::crypto::{Argon2Hasher, PasswordHasher};
use crate::validators::PasswordPolicy;
use crate::{AuthError, PasswordResetRepository, UserRepository};
use chrono::Utc;

pub struct ResetPasswordAction<U, P, H = Argon2Hasher>
where
    U: UserRepository,
    P: PasswordResetRepository,
{
    user_repository: U,
    reset_repository: P,
    password_policy: PasswordPolicy,
    hasher: H,
}

impl<U: UserRepository, P: PasswordResetRepository> ResetPasswordAction<U, P, Argon2Hasher> {
    /// Creates a new `ResetPasswordAction` with the default password policy and hasher.
    pub fn new(user_repository: U, reset_repository: P) -> Self {
        Self {
            user_repository,
            reset_repository,
            password_policy: PasswordPolicy::default(),
            hasher: Argon2Hasher::default(),
        }
    }

    /// Creates a new `ResetPasswordAction` with a custom password policy.
    pub fn with_policy(
        user_repository: U,
        reset_repository: P,
        password_policy: PasswordPolicy,
    ) -> Self {
        Self {
            user_repository,
            reset_repository,
            password_policy,
            hasher: Argon2Hasher::default(),
        }
    }
}

impl<U: UserRepository, P: PasswordResetRepository, H: PasswordHasher>
    ResetPasswordAction<U, P, H>
{
    /// Creates a new `ResetPasswordAction` with a custom password policy and hasher.
    pub fn with_hasher(
        user_repository: U,
        reset_repository: P,
        password_policy: PasswordPolicy,
        hasher: H,
    ) -> Self {
        Self {
            user_repository,
            reset_repository,
            password_policy,
            hasher,
        }
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "reset_password", skip_all, err)
    )]
    pub async fn execute(&self, token: &str, new_password: &SecretString) -> Result<(), AuthError> {
        self.password_policy
            .validate(new_password.expose_secret())?;

        let reset_token = self.reset_repository.find_reset_token(token).await?;

        match reset_token {
            Some(reset_token) => {
                if reset_token.expires_at < Utc::now() {
                    self.reset_repository.delete_reset_token(token).await?;
                    return Err(AuthError::TokenExpired);
                }

                let hashed = self.hasher.hash(new_password.expose_secret())?;
                self.user_repository
                    .update_password(reset_token.user_id, &hashed)
                    .await?;
                self.reset_repository.delete_reset_token(token).await?;

                let user_id = reset_token.user_id;
                log::info!(
                    target: "enclave_auth",
                    "msg=\"password reset success\", user_id={user_id}"
                );

                Ok(())
            }
            None => Err(AuthError::TokenInvalid)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretString;
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
        let new_password = SecretString::new("newpassword123");
        let result = action
            .execute(token.token.expose_secret(), &new_password)
            .await;

        assert!(result.is_ok());

        // Token should be deleted
        let found = action
            .reset_repository
            .find_reset_token(token.token.expose_secret())
            .await
            .unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_reset_password_invalid_token() {
        let user_repo = MockUserRepository::new();
        let reset_repo = MockPasswordResetRepository::new();

        let action = ResetPasswordAction::new(user_repo, reset_repo);
        let new_password = SecretString::new("newpassword123");
        let result = action.execute("invalid_token", &new_password).await;

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
        let new_password = SecretString::new("newpassword123");
        let result = action
            .execute(token.token.expose_secret(), &new_password)
            .await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::TokenExpired);
    }

    #[tokio::test]
    async fn test_reset_password_invalid_password() {
        let user_repo = MockUserRepository::new();
        let reset_repo = MockPasswordResetRepository::new();

        let action = ResetPasswordAction::new(user_repo, reset_repo);
        let new_password = SecretString::new("short");
        let result = action.execute("sometoken", &new_password).await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            AuthError::Validation(ValidationError::PasswordTooShort(8))
        );
    }
}
