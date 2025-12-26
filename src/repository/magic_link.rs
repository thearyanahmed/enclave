use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::AuthError;
use crate::SecretString;

/// A one-time token for magic link login.
///
/// Tokens are hashed before storage and single-use (deleted after successful login).
/// The `token` field uses `SecretString` to prevent accidental logging.
#[derive(Clone, Serialize, Deserialize)]
pub struct MagicLinkToken {
    pub token: SecretString,
    pub user_id: i32,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl std::fmt::Debug for MagicLinkToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MagicLinkToken")
            .field("token", &"[REDACTED]")
            .field("user_id", &self.user_id)
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Storage for magic link tokens.
///
/// Tokens should be deleted after use or expiration. Use `prune_expired` for periodic cleanup.
#[async_trait]
pub trait MagicLinkRepository {
    /// Creates a new magic link token for a user.
    async fn create_magic_link_token(
        &self,
        user_id: i32,
        expires_at: DateTime<Utc>,
    ) -> Result<MagicLinkToken, AuthError>;

    /// Finds a magic link token by its plaintext value.
    async fn find_magic_link_token(
        &self,
        token: &str,
    ) -> Result<Option<MagicLinkToken>, AuthError>;

    /// Deletes a magic link token after use.
    async fn delete_magic_link_token(&self, token: &str) -> Result<(), AuthError>;

    /// Removes all expired magic link tokens.
    ///
    /// Returns the number of tokens deleted. Run this periodically to clean up the database.
    async fn prune_expired(&self) -> Result<u64, AuthError>;
}
