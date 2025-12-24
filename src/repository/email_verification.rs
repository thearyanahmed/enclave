use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::crypto::SecretString;
use crate::AuthError;

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
#[async_trait]
pub trait EmailVerificationRepository {
    async fn create_verification_token(
        &self,
        user_id: i32,
        expires_at: DateTime<Utc>,
    ) -> Result<EmailVerificationToken, AuthError>;
    async fn find_verification_token(
        &self,
        token: &str,
    ) -> Result<Option<EmailVerificationToken>, AuthError>;
    async fn delete_verification_token(&self, token: &str) -> Result<(), AuthError>;
}
