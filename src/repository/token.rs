use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::AuthError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    pub token: String,
    pub user_id: i32,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[async_trait]
pub trait TokenRepository {
    async fn create_token(
        &self,
        user_id: i32,
        expires_at: DateTime<Utc>,
    ) -> Result<AccessToken, AuthError>;
    async fn find_token(&self, token: &str) -> Result<Option<AccessToken>, AuthError>;
    async fn revoke_token(&self, token: &str) -> Result<(), AuthError>;
    async fn revoke_all_user_tokens(&self, user_id: i32) -> Result<(), AuthError>;
}
