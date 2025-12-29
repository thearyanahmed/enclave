use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::AuthError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditEventType {
    Signup,
    LoginSuccess,
    LoginFailed,
    Logout,
    PasswordChanged,
    PasswordResetRequested,
    PasswordReset,
    EmailVerificationSent,
    EmailVerified,
    TokenRefreshed,
    AccountDeleted,
}

/// `user_id` is `None` for failed login attempts where the user doesn't exist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: i64,
    pub user_id: Option<i64>,
    pub event_type: AuditEventType,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub metadata: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[async_trait]
pub trait AuditLogRepository {
    async fn log_event(
        &self,
        user_id: Option<i64>,
        event_type: AuditEventType,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        metadata: Option<&str>,
    ) -> Result<AuditLog, AuthError>;
    async fn get_user_events(&self, user_id: i64, limit: usize)
    -> Result<Vec<AuditLog>, AuthError>;
}
