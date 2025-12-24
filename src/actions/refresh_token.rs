use crate::{AccessToken, AuthError, StatefulTokenRepository};
use chrono::{Duration, Utc};

/// Configuration for token refresh behavior.
#[derive(Debug, Clone)]
pub struct RefreshTokenConfig {
    /// How long the new access token remains valid after refresh.
    ///
    /// Default: 7 days
    pub access_token_expiry: Duration,
}

impl Default for RefreshTokenConfig {
    fn default() -> Self {
        Self {
            access_token_expiry: Duration::days(7),
        }
    }
}

impl RefreshTokenConfig {
    /// Creates config from a `TokenConfig`.
    pub fn from_token_config(tokens: &crate::config::TokenConfig) -> Self {
        Self {
            access_token_expiry: tokens.access_token_expiry,
        }
    }
}

/// Refreshes an access token by revoking the old one and issuing a new one.
///
/// This action requires a [`StatefulTokenRepository`] because it needs to:
/// 1. Validate the current token exists
/// 2. Revoke the old token
/// 3. Create a new token
///
/// For stateless tokens like JWT, token refresh is typically handled differently
/// (e.g., by issuing a new JWT before the old one expires).
pub struct RefreshTokenAction<T: StatefulTokenRepository> {
    token_repository: T,
    config: RefreshTokenConfig,
}

impl<T: StatefulTokenRepository> RefreshTokenAction<T> {
    pub fn new(token_repository: T) -> Self {
        Self::with_config(token_repository, RefreshTokenConfig::default())
    }

    pub fn with_config(token_repository: T, config: RefreshTokenConfig) -> Self {
        RefreshTokenAction {
            token_repository,
            config,
        }
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
                let new_expires_at = Utc::now() + self.config.access_token_expiry;
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
    use crate::{MockTokenRepository, TokenRepository};
    use chrono::Duration;

    #[tokio::test]
    async fn test_refresh_token_success() {
        let token_repo = MockTokenRepository::new();

        let expires_at = Utc::now() + Duration::hours(1);
        let original_token = token_repo.create_token(1, expires_at).await.unwrap();

        let action = RefreshTokenAction::new(token_repo);
        let result = action.execute(original_token.token.expose_secret()).await;

        assert!(result.is_ok());
        let new_token = result.unwrap();
        assert_eq!(new_token.user_id, 1);
        assert_ne!(
            new_token.token.expose_secret(),
            original_token.token.expose_secret()
        );

        // Old token should be revoked
        let old_found = action
            .token_repository
            .find_token(original_token.token.expose_secret())
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
        let result = action.execute(original_token.token.expose_secret()).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::TokenExpired);
    }
}
