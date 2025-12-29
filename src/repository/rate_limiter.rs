use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::AuthError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginAttempt {
    pub email: String,
    pub success: bool,
    pub ip_address: Option<String>,
    pub attempted_at: DateTime<Utc>,
}

#[async_trait]
pub trait RateLimiterRepository {
    async fn record_attempt(
        &self,
        email: &str,
        success: bool,
        ip_address: Option<&str>,
    ) -> Result<(), AuthError>;
    async fn get_recent_failed_attempts(
        &self,
        email: &str,
        since: DateTime<Utc>,
    ) -> Result<u32, AuthError>;
    async fn clear_attempts(&self, email: &str) -> Result<(), AuthError>;
}
