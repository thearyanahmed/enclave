use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::AuthError;
use crate::SecretString;

/// A one-time token sent to users to verify their email address.
///
/// The `token` field uses `SecretString` to prevent accidental logging.
#[derive(Clone, Serialize, Deserialize)]
pub struct EmailVerificationToken {
    pub token: SecretString,
    pub user_id: i32,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl std::fmt::Debug for EmailVerificationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailVerificationToken")
            .field("token", &"[REDACTED]")
            .field("user_id", &self.user_id)
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Storage for email verification tokens.
///
/// Tokens should be deleted after use or expiration. Use `prune_expired` for periodic cleanup.
#[async_trait]
pub trait EmailVerificationRepository {
    /// Creates a new email verification token for a user.
    async fn create_verification_token(
        &self,
        user_id: i32,
        expires_at: DateTime<Utc>,
    ) -> Result<EmailVerificationToken, AuthError>;

    /// Finds an email verification token by its plaintext value.
    async fn find_verification_token(
        &self,
        token: &str,
    ) -> Result<Option<EmailVerificationToken>, AuthError>;

    /// Deletes an email verification token after use.
    async fn delete_verification_token(&self, token: &str) -> Result<(), AuthError>;

    /// Removes all expired email verification tokens.
    ///
    /// Returns the number of tokens deleted. Run this periodically to clean up the database.
    async fn prune_expired(&self) -> Result<u64, AuthError>;
}
