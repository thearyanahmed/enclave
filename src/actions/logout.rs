use crate::{AuthError, StatefulTokenRepository};

/// requires `StatefulTokenRepository` - JWT tokens are stateless and cannot be revoked server-side
pub struct LogoutAction<T: StatefulTokenRepository> {
    token_repository: T,
}

impl<T: StatefulTokenRepository> LogoutAction<T> {
    /// Creates a new `LogoutAction`.
    ///
    /// Revokes the provided access token, invalidating the user's session.
    pub fn new(token_repository: T) -> Self {
        LogoutAction { token_repository }
    }

    /// Logs out a user by revoking their access token.
    ///
    /// # Returns
    ///
    /// - `Ok(())` - token revoked successfully
    /// - `Err(_)` - database or other errors
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "logout", skip_all, err)
    )]
    pub async fn execute(&self, token: &str) -> Result<(), AuthError> {
        self.token_repository.revoke_token(token).await?;

        log::info!(
            target: "enclave_auth",
            "msg=\"logout success\""
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};

    use super::*;
    use crate::{MockTokenRepository, TokenRepository};

    #[tokio::test]
    async fn test_logout_revokes_token() {
        let token_repo = MockTokenRepository::new();

        let expires_at = Utc::now() + Duration::days(7);
        let token = token_repo.create_token(1, expires_at).await.unwrap();

        let found = token_repo
            .find_token(token.token.expose_secret())
            .await
            .unwrap();
        assert!(found.is_some());

        let logout = LogoutAction::new(token_repo);
        let result = logout.execute(token.token.expose_secret()).await;
        assert!(result.is_ok());

        let found = logout
            .token_repository
            .find_token(token.token.expose_secret())
            .await
            .unwrap();
        assert!(found.is_none());
    }
}
