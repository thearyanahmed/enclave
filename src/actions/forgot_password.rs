use crate::{AuthError, PasswordResetRepository, PasswordResetToken, UserRepository};
use chrono::{Duration, Utc};

#[cfg(feature = "tracing")]
use crate::TracingConfig;

pub struct ForgotPasswordAction<U: UserRepository, P: PasswordResetRepository> {
    user_repository: U,
    reset_repository: P,
    #[cfg(feature = "tracing")]
    tracing: Option<TracingConfig>,
}

impl<U: UserRepository, P: PasswordResetRepository> ForgotPasswordAction<U, P> {
    pub fn new(user_repository: U, reset_repository: P) -> Self {
        ForgotPasswordAction {
            user_repository,
            reset_repository,
            #[cfg(feature = "tracing")]
            tracing: None,
        }
    }

    #[cfg(feature = "tracing")]
    pub fn with_tracing(mut self) -> Self {
        self.tracing = Some(TracingConfig::new("forgot_password"));
        self
    }

    #[cfg(feature = "tracing")]
    pub fn with_tracing_config(mut self, config: TracingConfig) -> Self {
        self.tracing = Some(config);
        self
    }

    pub async fn execute(&self, email: &str) -> Result<PasswordResetToken, AuthError> {
        #[cfg(feature = "tracing")]
        {
            if let Some(ref config) = self.tracing {
                use tracing::Instrument;
                let span = tracing::info_span!("action", name = config.span_name);
                let result = self.execute_inner(email).instrument(span).await;
                match &result {
                    Ok(_) => tracing::info!("forgot password token created"),
                    Err(e) => tracing::warn!(error = %e, "forgot password failed"),
                }
                return result;
            }
        }

        self.execute_inner(email).await
    }

    async fn execute_inner(&self, email: &str) -> Result<PasswordResetToken, AuthError> {
        let user = self.user_repository.find_user_by_email(email).await?;

        match user {
            Some(user) => {
                let expires_at = Utc::now() + Duration::hours(1);
                self.reset_repository
                    .create_reset_token(user.id, expires_at)
                    .await
            }
            None => Err(AuthError::UserNotFound),
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
        assert_eq!(token.user_id, user.id);
        assert!(!token.token.is_empty());
    }

    #[tokio::test]
    async fn test_forgot_password_user_not_found() {
        let user_repo = MockUserRepository::new();
        let reset_repo = MockPasswordResetRepository::new();

        let action = ForgotPasswordAction::new(user_repo, reset_repo);
        let result = action.execute("nonexistent@example.com").await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::UserNotFound);
    }
}
