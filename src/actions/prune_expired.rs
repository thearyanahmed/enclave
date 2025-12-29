//! run periodically (e.g., via cron) to clean up expired tokens and prevent unbounded table growth.

use crate::{
    AuthError, EmailVerificationRepository, PasswordResetRepository, StatefulTokenRepository,
};

#[derive(Debug, Clone, Default)]
pub struct PruneResult {
    pub access_tokens: u64,
    pub password_reset_tokens: u64,
    pub email_verification_tokens: u64,
}

impl PruneResult {
    pub fn total(&self) -> u64 {
        self.access_tokens + self.password_reset_tokens + self.email_verification_tokens
    }
}

pub struct PruneExpiredTokensAction<T, P, E> {
    tokens: T,
    password_resets: P,
    email_verifications: E,
}

impl<T, P, E> PruneExpiredTokensAction<T, P, E>
where
    T: StatefulTokenRepository,
    P: PasswordResetRepository,
    E: EmailVerificationRepository,
{
    /// Creates a new `PruneExpiredTokensAction`.
    ///
    /// Run periodically (e.g., via cron or background task) to clean up
    /// expired tokens and prevent unbounded table growth.
    pub fn new(tokens: T, password_resets: P, email_verifications: E) -> Self {
        Self {
            tokens,
            password_resets,
            email_verifications,
        }
    }

    /// Removes all expired tokens from the database.
    ///
    /// # Returns
    ///
    /// - `Ok(result)` - counts of pruned tokens by type
    /// - `Err(_)` - database or other errors
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(skip(self), name = "prune_expired")
    )]
    pub async fn execute(&self) -> Result<PruneResult, AuthError> {
        let access_tokens = self.tokens.prune_expired().await?;
        let password_reset_tokens = self.password_resets.prune_expired().await?;
        let email_verification_tokens = self.email_verifications.prune_expired().await?;

        log::info!(
            target: "enclave_auth",
            "msg=\"tokens pruned\", access_tokens={access_tokens}, password_reset_tokens={password_reset_tokens}, email_verification_tokens={email_verification_tokens}"
        );

        Ok(PruneResult {
            access_tokens,
            password_reset_tokens,
            email_verification_tokens,
        })
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};

    use super::*;
    use crate::{
        EmailVerificationRepository, MockEmailVerificationRepository, MockPasswordResetRepository,
        MockTokenRepository, PasswordResetRepository, TokenRepository,
    };

    #[tokio::test]
    async fn test_prune_expired_tokens() {
        let token_repo = MockTokenRepository::new();
        let password_reset_repo = MockPasswordResetRepository::new();
        let email_verification_repo = MockEmailVerificationRepository::new();

        // Create some expired tokens
        let expired = Utc::now() - Duration::hours(1);
        let valid = Utc::now() + Duration::hours(1);

        // Create expired and valid access tokens
        token_repo.create_token(1, expired).await.unwrap();
        token_repo.create_token(2, valid).await.unwrap();

        // Create expired and valid password reset tokens
        password_reset_repo
            .create_reset_token(1, expired)
            .await
            .unwrap();
        password_reset_repo
            .create_reset_token(2, valid)
            .await
            .unwrap();

        // Create expired and valid email verification tokens
        email_verification_repo
            .create_verification_token(1, expired)
            .await
            .unwrap();
        email_verification_repo
            .create_verification_token(2, valid)
            .await
            .unwrap();

        let action = PruneExpiredTokensAction::new(
            token_repo.clone(),
            password_reset_repo.clone(),
            email_verification_repo.clone(),
        );

        let result = action.execute().await.unwrap();

        assert_eq!(result.access_tokens, 1);
        assert_eq!(result.password_reset_tokens, 1);
        assert_eq!(result.email_verification_tokens, 1);
        assert_eq!(result.total(), 3);

        // Verify only valid tokens remain
        assert_eq!(token_repo.tokens.lock().unwrap().len(), 1);
        assert_eq!(password_reset_repo.tokens.lock().unwrap().len(), 1);
        assert_eq!(email_verification_repo.tokens.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_prune_no_expired_tokens() {
        let token_repo = MockTokenRepository::new();
        let password_reset_repo = MockPasswordResetRepository::new();
        let email_verification_repo = MockEmailVerificationRepository::new();

        let action =
            PruneExpiredTokensAction::new(token_repo, password_reset_repo, email_verification_repo);

        let result = action.execute().await.unwrap();

        assert_eq!(result.access_tokens, 0);
        assert_eq!(result.password_reset_tokens, 0);
        assert_eq!(result.email_verification_tokens, 0);
        assert_eq!(result.total(), 0);
    }
}
