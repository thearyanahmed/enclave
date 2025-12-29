use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{AuthError, SecretString};

#[derive(Clone, Serialize, Deserialize)]
pub struct AccessToken {
    pub token: SecretString,
    pub user_id: i64,
    pub name: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl std::fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessToken")
            .field("token", &"[REDACTED]")
            .field("user_id", &self.user_id)
            .field("name", &self.name)
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[derive(Debug, Clone, Default)]
pub struct CreateTokenOptions {
    pub name: Option<String>,
}

#[async_trait]
pub trait TokenRepository: Send + Sync {
    async fn create_token(
        &self,
        user_id: i64,
        expires_at: DateTime<Utc>,
    ) -> Result<AccessToken, AuthError>;

    async fn create_token_with_options(
        &self,
        user_id: i64,
        expires_at: DateTime<Utc>,
        options: CreateTokenOptions,
    ) -> Result<AccessToken, AuthError>;

    async fn find_token(&self, token: &str) -> Result<Option<AccessToken>, AuthError>;
}

#[async_trait]
pub trait StatefulTokenRepository: TokenRepository {
    async fn revoke_token(&self, token: &str) -> Result<(), AuthError>;

    async fn revoke_all_user_tokens(&self, user_id: i64) -> Result<(), AuthError>;

    async fn prune_expired(&self) -> Result<i64, AuthError>;
}
