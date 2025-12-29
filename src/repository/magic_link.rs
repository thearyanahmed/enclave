use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{AuthError, SecretString};

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

#[async_trait]
pub trait MagicLinkRepository {
    async fn create_magic_link_token(
        &self,
        user_id: i32,
        expires_at: DateTime<Utc>,
    ) -> Result<MagicLinkToken, AuthError>;

    async fn find_magic_link_token(&self, token: &str)
    -> Result<Option<MagicLinkToken>, AuthError>;

    async fn delete_magic_link_token(&self, token: &str) -> Result<(), AuthError>;

    async fn prune_expired(&self) -> Result<u64, AuthError>;
}
