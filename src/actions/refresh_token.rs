use chrono::{Duration, Utc};

use crate::events::{AuthEvent, dispatch};
use crate::{AccessToken, AuthError, StatefulTokenRepository};

#[derive(Debug, Clone)]
pub struct RefreshTokenConfig {
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
    pub fn from_token_config(tokens: &crate::config::TokenConfig) -> Self {
        Self {
            access_token_expiry: tokens.access_token_expiry,
        }
    }
}

/// requires `StatefulTokenRepository` - JWT uses a different refresh mechanism
pub struct RefreshTokenAction<T: StatefulTokenRepository> {
    token_repository: T,
    config: RefreshTokenConfig,
}

impl<T: StatefulTokenRepository> RefreshTokenAction<T> {
    /// Creates a new `RefreshTokenAction` with default configuration.
    ///
    /// Default: 7 day access token expiry. For custom settings, use [`with_config`].
    ///
    /// [`with_config`]: Self::with_config
    pub fn new(token_repository: T) -> Self {
        Self::with_config(token_repository, RefreshTokenConfig::default())
    }

    /// Creates a new `RefreshTokenAction` with custom configuration.
    ///
    /// Use [`RefreshTokenConfig::from_token_config`] to build from `TokenConfig`.
    ///
    /// [`RefreshTokenConfig::from_token_config`]: RefreshTokenConfig::from_token_config
    pub fn with_config(token_repository: T, config: RefreshTokenConfig) -> Self {
        RefreshTokenAction {
            token_repository,
            config,
        }
    }

    /// Refreshes an access token, returning a new token with extended expiry.
    ///
    /// The old token is revoked and a new one is issued.
    ///
    /// # Returns
    ///
    /// - `Ok(token)` - new access token with fresh expiry
    /// - `Err(AuthError::TokenInvalid)` - token not found or already revoked
    /// - `Err(AuthError::TokenExpired)` - token has expired
    /// - `Err(_)` - database or other errors
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
                let new_token = self
                    .token_repository
                    .create_token(token.user_id, new_expires_at)
                    .await?;

                dispatch(AuthEvent::TokenRefreshed {
                    user_id: token.user_id,
                    at: Utc::now(),
                })
                .await;

                log::info!(
                    target: "enclave_auth",
                    "msg=\"token refreshed\", user_id={}",
                    token.user_id
                );

                Ok(new_token)
            }
            None => Err(AuthError::TokenInvalid),
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;
    use crate::{MockTokenRepository, TokenRepository};

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
