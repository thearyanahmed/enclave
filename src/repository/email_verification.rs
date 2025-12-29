use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{AuthError, SecretString};

#[derive(Clone, Serialize, Deserialize)]
pub struct EmailVerificationToken {
    pub token: SecretString,
    pub user_id: u64,
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

#[async_trait]
pub trait EmailVerificationRepository {
    async fn create_verification_token(
        &self,
        user_id: u64,
        expires_at: DateTime<Utc>,
    ) -> Result<EmailVerificationToken, AuthError>;

    async fn find_verification_token(
        &self,
        token: &str,
    ) -> Result<Option<EmailVerificationToken>, AuthError>;

    async fn delete_verification_token(&self, token: &str) -> Result<(), AuthError>;

    async fn prune_expired(&self) -> Result<u64, AuthError>;
}
