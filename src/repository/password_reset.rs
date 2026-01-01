use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{AuthError, SecretString};

#[derive(Clone, Serialize, Deserialize)]
pub struct PasswordResetToken {
    pub token: SecretString,
    pub user_id: i64,
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

#[async_trait]
pub trait PasswordResetRepository {
    async fn create_reset_token(
        &self,
        user_id: i64,
        expires_at: DateTime<Utc>,
    ) -> Result<PasswordResetToken, AuthError>;

    async fn find_reset_token(&self, token: &str) -> Result<Option<PasswordResetToken>, AuthError>;

    async fn delete_reset_token(&self, token: &str) -> Result<(), AuthError>;

    async fn prune_expired(&self) -> Result<i64, AuthError>;
}
