use chrono::{Duration, Utc};

use crate::config::TokenConfig;
use crate::{
    AccessToken, AuthError, AuthUser, MagicLinkRepository, TokenRepository, UserRepository,
};

#[derive(Debug, Clone)]
pub struct VerifyMagicLinkConfig {
    pub access_token_expiry: Duration,
}

impl Default for VerifyMagicLinkConfig {
    fn default() -> Self {
        Self {
            access_token_expiry: Duration::days(7),
        }
    }
}

impl VerifyMagicLinkConfig {
    pub fn from_token_config(tokens: &TokenConfig) -> Self {
        Self {
            access_token_expiry: tokens.access_token_expiry,
        }
    }
}

pub struct VerifyMagicLinkAction<U, T, M>
where
    U: UserRepository,
    T: TokenRepository,
    M: MagicLinkRepository,
{
    user_repository: U,
    token_repository: T,
    magic_link_repository: M,
    config: VerifyMagicLinkConfig,
}

impl<U: UserRepository, T: TokenRepository, M: MagicLinkRepository> VerifyMagicLinkAction<U, T, M> {
    /// Creates a new `VerifyMagicLinkAction` with default configuration.
    ///
    /// Default: 7 day access token expiry. For custom settings, use [`with_config`].
    ///
    /// [`with_config`]: Self::with_config
    pub fn new(user_repository: U, token_repository: T, magic_link_repository: M) -> Self {
        Self::with_config(
            user_repository,
            token_repository,
            magic_link_repository,
            VerifyMagicLinkConfig::default(),
        )
    }

    /// Creates a new `VerifyMagicLinkAction` with custom configuration.
    pub fn with_config(
        user_repository: U,
        token_repository: T,
        magic_link_repository: M,
        config: VerifyMagicLinkConfig,
    ) -> Self {
        VerifyMagicLinkAction {
            user_repository,
            token_repository,
            magic_link_repository,
            config,
        }
    }

    #[must_use]
    pub fn config(mut self, config: VerifyMagicLinkConfig) -> Self {
        self.config = config;
        self
    }

    /// Verifies a magic link token and returns an authenticated session.
    ///
    /// Magic link tokens are single-use and deleted after verification.
    ///
    /// # Returns
    ///
    /// - `Ok((user, token))` - valid magic link, returns user and access token
    /// - `Err(AuthError::TokenInvalid)` - invalid, expired, or already used token
    /// - `Err(_)` - database or other errors
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "verify_magic_link", skip_all, err)
    )]
    pub async fn execute(&self, token: &str) -> Result<(AuthUser, AccessToken), AuthError> {
        let magic_link_token = self
            .magic_link_repository
            .find_magic_link_token(token)
            .await?
            .ok_or(AuthError::TokenInvalid)?;

        if magic_link_token.expires_at < Utc::now() {
            self.magic_link_repository
                .delete_magic_link_token(token)
                .await?;
            return Err(AuthError::TokenInvalid);
        }

        let user = self
            .user_repository
            .find_user_by_id(magic_link_token.user_id)
            .await?
            .ok_or(AuthError::TokenInvalid)?;

        self.magic_link_repository
            .delete_magic_link_token(token)
            .await?;

        let expires_at = Utc::now() + self.config.access_token_expiry;
        let access_token = self
            .token_repository
            .create_token(user.id, expires_at)
            .await?;

        let user_id = user.id;
        log::info!(
            target: "enclave_auth",
            "msg=\"magic link login success\", user_id={user_id}"
        );

        Ok((user, access_token))
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;
    use crate::{AuthUser, MockMagicLinkRepository, MockTokenRepository, MockUserRepository};

    #[tokio::test]
    async fn test_verify_magic_link_success() {
        let user_repo = MockUserRepository::new();
        let token_repo = MockTokenRepository::new();
        let magic_link_repo = MockMagicLinkRepository::new();

        let user = AuthUser::mock_from_email("user@example.com");
        user_repo.users.lock().unwrap().push(user.clone());

        // Create a magic link token
        let expires_at = Utc::now() + Duration::minutes(15);
        let magic_link_token = magic_link_repo
            .create_magic_link_token(user.id, expires_at)
            .await
            .unwrap();

        let action = VerifyMagicLinkAction::new(user_repo, token_repo, magic_link_repo.clone());
        let result = action.execute(magic_link_token.token.expose_secret()).await;

        assert!(result.is_ok());
        let (returned_user, access_token) = result.unwrap();
        assert_eq!(returned_user.id, user.id);
        assert_eq!(returned_user.email, user.email);
        assert!(!access_token.token.is_empty());
        assert_eq!(access_token.user_id, user.id);

        // Token should be deleted (single-use)
        let found = magic_link_repo
            .find_magic_link_token(magic_link_token.token.expose_secret())
            .await
            .unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_verify_magic_link_invalid_token() {
        let user_repo = MockUserRepository::new();
        let token_repo = MockTokenRepository::new();
        let magic_link_repo = MockMagicLinkRepository::new();

        let action = VerifyMagicLinkAction::new(user_repo, token_repo, magic_link_repo);
        let result = action.execute("nonexistent_token").await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::TokenInvalid);
    }

    #[tokio::test]
    async fn test_verify_magic_link_expired_token() {
        let user_repo = MockUserRepository::new();
        let token_repo = MockTokenRepository::new();
        let magic_link_repo = MockMagicLinkRepository::new();

        let user = AuthUser::mock_from_email("user@example.com");
        user_repo.users.lock().unwrap().push(user.clone());

        // Create an expired magic link token
        let expires_at = Utc::now() - Duration::minutes(1);
        let magic_link_token = magic_link_repo
            .create_magic_link_token(user.id, expires_at)
            .await
            .unwrap();

        let action = VerifyMagicLinkAction::new(user_repo, token_repo, magic_link_repo.clone());
        let result = action.execute(magic_link_token.token.expose_secret()).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::TokenInvalid);

        // Expired token should be deleted
        let found = magic_link_repo
            .find_magic_link_token(magic_link_token.token.expose_secret())
            .await
            .unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_verify_magic_link_user_deleted() {
        let user_repo = MockUserRepository::new();
        let token_repo = MockTokenRepository::new();
        let magic_link_repo = MockMagicLinkRepository::new();

        // Create token for user that doesn't exist in repo
        let expires_at = Utc::now() + Duration::minutes(15);
        let magic_link_token = magic_link_repo
            .create_magic_link_token(999, expires_at)
            .await
            .unwrap();

        let action = VerifyMagicLinkAction::new(user_repo, token_repo, magic_link_repo);
        let result = action.execute(magic_link_token.token.expose_secret()).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::TokenInvalid);
    }

    #[tokio::test]
    async fn test_verify_magic_link_single_use() {
        let user_repo = MockUserRepository::new();
        let token_repo = MockTokenRepository::new();
        let magic_link_repo = MockMagicLinkRepository::new();

        let user = AuthUser::mock_from_email("user@example.com");
        user_repo.users.lock().unwrap().push(user.clone());

        // Create a magic link token
        let expires_at = Utc::now() + Duration::minutes(15);
        let magic_link_token = magic_link_repo
            .create_magic_link_token(user.id, expires_at)
            .await
            .unwrap();

        let action = VerifyMagicLinkAction::new(user_repo, token_repo, magic_link_repo);
        let token_str = magic_link_token.token.expose_secret().to_owned();

        // First use should succeed
        let result1 = action.execute(&token_str).await;
        assert!(result1.is_ok());

        // Second use should fail
        let result2 = action.execute(&token_str).await;
        assert!(result2.is_err());
        assert_eq!(result2.unwrap_err(), AuthError::TokenInvalid);
    }
}
