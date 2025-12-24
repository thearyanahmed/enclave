use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::AuthError;
use crate::SecretString;

/// A one-time token for password reset requests.
///
/// Tokens are hashed before storage and single-use (deleted after password change).
/// The `token` field uses `SecretString` to prevent accidental logging.
#[derive(Clone, Serialize, Deserialize)]
pub struct PasswordResetToken {
    pub token: SecretString,
    pub user_id: i32,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl std::fmt::Debug for PasswordResetToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordResetToken")
            .field("token", &"[REDACTED]")
            .field("user_id", &self.user_id)
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Storage for password reset tokens.
///
/// Tokens should be deleted after use or expiration. Consider running periodic cleanup.
#[async_trait]
pub trait PasswordResetRepository {
    async fn create_reset_token(
        &self,
        user_id: i32,
        expires_at: DateTime<Utc>,
    ) -> Result<PasswordResetToken, AuthError>;
    async fn find_reset_token(&self, token: &str) -> Result<Option<PasswordResetToken>, AuthError>;
    async fn delete_reset_token(&self, token: &str) -> Result<(), AuthError>;
}
