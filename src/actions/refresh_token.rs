use crate::{AccessToken, AuthError, TokenRepository};
use chrono::{Duration, Utc};

pub struct RefreshTokenAction<T: TokenRepository> {
    token_repository: T,
}

impl<T: TokenRepository> RefreshTokenAction<T> {
    pub fn new(token_repository: T) -> Self {
        RefreshTokenAction { token_repository }
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "refresh_token", skip_all, err)
    )]
    pub async fn execute(&self, current_token: &str) -> Result<AccessToken, AuthError> {
        let token = self.token_repository.find_token(current_token).await?;

        match token {
            Some(token) => {
                if token.expires_at < Utc::now() {
                    self.token_repository.revoke_token(current_token).await?;
                    return Err(AuthError::TokenExpired);
                }

                // Revoke old token and create new one
                self.token_repository.revoke_token(current_token).await?;
                let new_expires_at = Utc::now() + Duration::days(7);
                self.token_repository
                    .create_token(token.user_id, new_expires_at)
                    .await
            }
            None => Err(AuthError::TokenInvalid),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockTokenRepository;
    use chrono::Duration;

    #[tokio::test]
    async fn test_refresh_token_success() {
        let token_repo = MockTokenRepository::new();

        let expires_at = Utc::now() + Duration::hours(1);
        let original_token = token_repo.create_token(1, expires_at).await.unwrap();

        let action = RefreshTokenAction::new(token_repo);
        let result = action.execute(&original_token.token).await;

        assert!(result.is_ok());
        let new_token = result.unwrap();
        assert_eq!(new_token.user_id, 1);
        assert_ne!(new_token.token, original_token.token);

        // Old token should be revoked
        let old_found = action
            .token_repository
            .find_token(&original_token.token)
            .await
            .unwrap();
        assert!(old_found.is_none());
    }

    #[tokio::test]
    async fn test_refresh_token_invalid() {
        let token_repo = MockTokenRepository::new();

        let action = RefreshTokenAction::new(token_repo);
        let result = action.execute("invalid_token").await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::TokenInvalid);
    }

    #[tokio::test]
    async fn test_refresh_token_expired() {
        let token_repo = MockTokenRepository::new();

        let expires_at = Utc::now() - Duration::hours(1); // Already expired
        let original_token = token_repo.create_token(1, expires_at).await.unwrap();

        let action = RefreshTokenAction::new(token_repo);
        let result = action.execute(&original_token.token).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::TokenExpired);
    }
}
