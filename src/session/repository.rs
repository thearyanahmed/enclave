//! Session repository trait.

use crate::AuthError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::{Session, SessionData};

/// Repository for session storage.
///
/// Implementations provide different storage backends:
/// - [`InMemorySessionRepository`](super::InMemorySessionRepository): In-memory storage for testing
/// - [`FileSessionRepository`](super::FileSessionRepository): File-based storage
#[async_trait]
pub trait SessionRepository: Send + Sync {
    /// Creates a new session and returns the session ID.
    async fn create(&self, data: SessionData) -> Result<String, AuthError>;

    /// Finds a session by its ID.
    async fn find(&self, session_id: &str) -> Result<Option<Session>, AuthError>;

    /// Extends a session's expiry time (for sliding window).
    async fn extend(
        &self,
        session_id: &str,
        new_expires_at: DateTime<Utc>,
    ) -> Result<(), AuthError>;

    /// Destroys a session.
    async fn destroy(&self, session_id: &str) -> Result<(), AuthError>;

    /// Destroys all sessions for a user.
    async fn destroy_user_sessions(&self, user_id: i32) -> Result<(), AuthError>;

    /// Removes expired sessions.
    ///
    /// Returns the number of sessions pruned.
    async fn prune_expired(&self) -> Result<u64, AuthError>;
}
