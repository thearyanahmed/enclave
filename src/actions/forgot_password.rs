use crate::{AuthError, PasswordResetRepository, PasswordResetToken, UserRepository};
use chrono::{Duration, Utc};

/// Configuration for password reset behavior.
#[derive(Debug, Clone)]
pub struct ForgotPasswordConfig {
    /// How long password reset tokens remain valid.
    ///
    /// Default: 1 hour
    pub password_reset_expiry: Duration,
}

impl Default for ForgotPasswordConfig {
    fn default() -> Self {
        Self {
            password_reset_expiry: Duration::hours(1),
        }
    }
}

impl ForgotPasswordConfig {
    /// Creates config from a `TokenConfig`.
    pub fn from_token_config(tokens: &crate::config::TokenConfig) -> Self {
        Self {
            password_reset_expiry: tokens.password_reset_expiry,
        }
    }
}

pub struct ForgotPasswordAction<U: UserRepository, P: PasswordResetRepository> {
    user_repository: U,
    reset_repository: P,
    config: ForgotPasswordConfig,
}

impl<U: UserRepository, P: PasswordResetRepository> ForgotPasswordAction<U, P> {
    pub fn new(user_repository: U, reset_repository: P) -> Self {
        Self::with_config(
            user_repository,
            reset_repository,
            ForgotPasswordConfig::default(),
        )
    }

    pub fn with_config(
        user_repository: U,
        reset_repository: P,
        config: ForgotPasswordConfig,
    ) -> Self {
        ForgotPasswordAction {
            user_repository,
            reset_repository,
            config,
        }
    }

    /// Initiates a password reset for the given email.
    ///
    /// Returns `Ok(Some(token))` if a user with that email exists and a reset token was created.
    /// Returns `Ok(None)` if no user exists with that email (prevents user enumeration).
    /// Returns `Err` only for actual errors (database failures, etc.).
    ///
    /// # Security
    ///
    /// This method intentionally does not reveal whether a user exists.
    /// Always show a generic message like "If an account exists, a reset email has been sent"
    /// regardless of the return value.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "forgot_password", skip_all, err)
    )]
    pub async fn execute(&self, email: &str) -> Result<Option<PasswordResetToken>, AuthError> {
        let user = self.user_repository.find_user_by_email(email).await?;

        match user {
            Some(user) => {
                let expires_at = Utc::now() + self.config.password_reset_expiry;
                let token = self
                    .reset_repository
                    .create_reset_token(user.id, expires_at)
                    .await?;
                Ok(Some(token))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MockPasswordResetRepository, MockUserRepository, User};

    #[tokio::test]
    async fn test_forgot_password_creates_token() {
        let user_repo = MockUserRepository::new();
        let reset_repo = MockPasswordResetRepository::new();

        let user = User::mock_from_email("user@example.com");
        user_repo.users.lock().unwrap().push(user.clone());

        let action = ForgotPasswordAction::new(user_repo, reset_repo);
        let result = action.execute("user@example.com").await;

        assert!(result.is_ok());
        let token = result.unwrap();
        assert!(token.is_some());
        let token = token.unwrap();
        assert_eq!(token.user_id, user.id);
        assert!(!token.token.is_empty());
    }

    #[tokio::test]
    async fn test_forgot_password_user_not_found_returns_none() {
        let user_repo = MockUserRepository::new();
        let reset_repo = MockPasswordResetRepository::new();

        let action = ForgotPasswordAction::new(user_repo, reset_repo);
        let result = action.execute("nonexistent@example.com").await;

        // Should succeed with None, not error (prevents user enumeration)
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
}
