use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::{Session, SessionData};
use crate::AuthError;

#[async_trait]
pub trait SessionRepository: Send + Sync {
    async fn create(&self, data: SessionData) -> Result<String, AuthError>;
    async fn find(&self, session_id: &str) -> Result<Option<Session>, AuthError>;
    async fn extend(
        &self,
        session_id: &str,
        new_expires_at: DateTime<Utc>,
    ) -> Result<(), AuthError>;
    async fn destroy(&self, session_id: &str) -> Result<(), AuthError>;
    async fn destroy_user_sessions(&self, user_id: i64) -> Result<(), AuthError>;
    async fn prune_expired(&self) -> Result<u64, AuthError>;
}
