use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::AuthError;

/// A recorded login attempt for rate limiting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginAttempt {
    pub email: String,
    pub success: bool,
    pub ip_address: Option<String>,
    pub attempted_at: DateTime<Utc>,
}

/// Storage for login attempt tracking to prevent brute-force attacks.
///
/// The default implementation locks accounts after 5 failed attempts within 15 minutes.
/// Successful logins clear the attempt history for that email.
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
    /// Removes all attempt records for an email (called after successful login).
    async fn clear_attempts(&self, email: &str) -> Result<(), AuthError>;
}
