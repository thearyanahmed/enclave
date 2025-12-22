use crate::{AuthError, EmailVerificationRepository, EmailVerificationToken, UserRepository};
use chrono::{Duration, Utc};

#[cfg(feature = "tracing")]
use crate::TracingConfig;

pub struct SendVerificationAction<U: UserRepository, E: EmailVerificationRepository> {
    user_repository: U,
    verification_repository: E,
    #[cfg(feature = "tracing")]
    tracing: Option<TracingConfig>,
}

impl<U: UserRepository, E: EmailVerificationRepository> SendVerificationAction<U, E> {
    pub fn new(user_repository: U, verification_repository: E) -> Self {
        SendVerificationAction {
            user_repository,
            verification_repository,
            #[cfg(feature = "tracing")]
            tracing: None,
        }
    }

    #[cfg(feature = "tracing")]
    pub fn with_tracing(mut self) -> Self {
        self.tracing = Some(TracingConfig::new("send_verification"));
        self
    }

    #[cfg(feature = "tracing")]
    pub fn with_tracing_config(mut self, config: TracingConfig) -> Self {
        self.tracing = Some(config);
        self
    }

    pub async fn execute(&self, user_id: i32) -> Result<EmailVerificationToken, AuthError> {
        #[cfg(feature = "tracing")]
        {
            if let Some(ref config) = self.tracing {
                use tracing::Instrument;
                let span = tracing::info_span!("action", name = config.span_name);
                let result = self.execute_inner(user_id).instrument(span).await;
                match &result {
                    Ok(_) => tracing::info!("verification email sent"),
                    Err(e) => tracing::warn!(error = %e, "send verification failed"),
                }
                return result;
            }
        }

        self.execute_inner(user_id).await
    }

    async fn execute_inner(&self, user_id: i32) -> Result<EmailVerificationToken, AuthError> {
        let user = self.user_repository.find_user_by_id(user_id).await?;

        match user {
            Some(user) => {
                if user.email_verified_at.is_some() {
                    return Err(AuthError::EmailAlreadyVerified);
                }

                let expires_at = Utc::now() + Duration::hours(24);
                self.verification_repository
                    .create_verification_token(user.id, expires_at)
                    .await
            }
            None => Err(AuthError::UserNotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MockEmailVerificationRepository, MockUserRepository, User};

    #[tokio::test]
    async fn test_send_verification_creates_token() {
        let user_repo = MockUserRepository::new();
        let verification_repo = MockEmailVerificationRepository::new();

        let user = User::mock_from_email("user@example.com");
        let user_id = user.id;
        user_repo.users.lock().unwrap().push(user);

        let action = SendVerificationAction::new(user_repo, verification_repo);
        let result = action.execute(user_id).await;

        assert!(result.is_ok());
        let token = result.unwrap();
        assert_eq!(token.user_id, user_id);
        assert!(!token.token.is_empty());
    }

    #[tokio::test]
    async fn test_send_verification_user_not_found() {
        let user_repo = MockUserRepository::new();
        let verification_repo = MockEmailVerificationRepository::new();

        let action = SendVerificationAction::new(user_repo, verification_repo);
        let result = action.execute(999).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::UserNotFound);
    }

    #[tokio::test]
    async fn test_send_verification_already_verified() {
        let user_repo = MockUserRepository::new();
        let verification_repo = MockEmailVerificationRepository::new();

        let mut user = User::mock_from_email("user@example.com");
        user.email_verified_at = Some(Utc::now());
        let user_id = user.id;
        user_repo.users.lock().unwrap().push(user);

        let action = SendVerificationAction::new(user_repo, verification_repo);
        let result = action.execute(user_id).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::EmailAlreadyVerified);
    }
}
