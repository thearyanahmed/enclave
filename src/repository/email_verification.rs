use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::AuthError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailVerificationToken {
    pub token: String,
    pub user_id: i32,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

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
