//! Action for cleaning up expired tokens from all repositories.
//!
//! This action removes expired access tokens, password reset tokens, and email verification
//! tokens from the database. Run it periodically (e.g., via a cron job) to prevent unbounded
//! table growth.
//!
//! # Example
//!
//! ```ignore
//! use enclave::actions::PruneExpiredTokensAction;
//!
//! let action = PruneExpiredTokensAction::new(
//!     token_repo,
//!     password_reset_repo,
//!     email_verification_repo,
//! );
//!
//! let result = action.execute().await?;
//! println!("Pruned {} access tokens", result.access_tokens);
//! println!("Pruned {} password reset tokens", result.password_reset_tokens);
//! println!("Pruned {} email verification tokens", result.email_verification_tokens);
//! ```

use crate::{
    AuthError, EmailVerificationRepository, PasswordResetRepository, StatefulTokenRepository,
};

/// Result of pruning expired tokens.
#[derive(Debug, Clone, Default)]
pub struct PruneResult {
    /// Number of expired access tokens removed.
    pub access_tokens: u64,
    /// Number of expired password reset tokens removed.
    pub password_reset_tokens: u64,
    /// Number of expired email verification tokens removed.
    pub email_verification_tokens: u64,
}

impl PruneResult {
    /// Returns the total number of tokens pruned across all types.
    pub fn total(&self) -> u64 {
        self.access_tokens + self.password_reset_tokens + self.email_verification_tokens
    }
}

/// Action for pruning expired tokens from all token repositories.
///
/// This is a maintenance action that should be run periodically to clean up
/// expired tokens and prevent unbounded database growth.
pub struct PruneExpiredTokensAction<T, P, E> {
    token_repo: T,
    password_reset_repo: P,
    email_verification_repo: E,
}

impl<T, P, E> PruneExpiredTokensAction<T, P, E>
where
    T: StatefulTokenRepository,
    P: PasswordResetRepository,
    E: EmailVerificationRepository,
{
    /// Creates a new prune action with the given repositories.
    pub fn new(token_repo: T, password_reset_repo: P, email_verification_repo: E) -> Self {
        Self {
            token_repo,
            password_reset_repo,
            email_verification_repo,
        }
    }

    /// Prunes all expired tokens from all repositories.
    ///
    /// Returns a [`PruneResult`] with the count of tokens removed from each repository.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), name = "prune_expired"))]
    pub async fn execute(&self) -> Result<PruneResult, AuthError> {
        let access_tokens = self.token_repo.prune_expired().await?;
        let password_reset_tokens = self.password_reset_repo.prune_expired().await?;
        let email_verification_tokens = self.email_verification_repo.prune_expired().await?;

        Ok(PruneResult {
            access_tokens,
            password_reset_tokens,
            email_verification_tokens,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        EmailVerificationRepository, MockEmailVerificationRepository, MockPasswordResetRepository,
        MockTokenRepository, PasswordResetRepository, TokenRepository,
    };
    use chrono::{Duration, Utc};

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

        let action = PruneExpiredTokensAction::new(
            token_repo,
            password_reset_repo,
            email_verification_repo,
        );

        let result = action.execute().await.unwrap();

        assert_eq!(result.access_tokens, 0);
        assert_eq!(result.password_reset_tokens, 0);
        assert_eq!(result.email_verification_tokens, 0);
        assert_eq!(result.total(), 0);
    }
}
