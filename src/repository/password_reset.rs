use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::AuthError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordResetToken {
    pub token: String,
    pub user_id: i32,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

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
