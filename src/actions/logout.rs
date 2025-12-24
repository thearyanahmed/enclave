use crate::{AuthError, StatefulTokenRepository};

/// Logs out a user by revoking their access token.
///
/// This action requires a [`StatefulTokenRepository`] because token revocation
/// is only possible with stateful (database-backed) tokens. For stateless tokens
/// like JWT, logout is handled client-side by discarding the token.
///
/// # Example
///
/// ```rust,ignore
/// let logout = LogoutAction::new(postgres_token_repo);
/// logout.execute("user_token_here").await?;
/// ```
pub struct LogoutAction<T: StatefulTokenRepository> {
    token_repository: T,
}

impl<T: StatefulTokenRepository> LogoutAction<T> {
    pub fn new(token_repository: T) -> Self {
        LogoutAction { token_repository }
    }

    /// Revokes the given access token, effectively logging the user out.
    ///
    /// After this call, the token will no longer be valid for authentication.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "logout", skip_all, err)
    )]
    pub async fn execute(&self, token: &str) -> Result<(), AuthError> {
        self.token_repository.revoke_token(token).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MockTokenRepository, TokenRepository};
    use chrono::{Duration, Utc};

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
