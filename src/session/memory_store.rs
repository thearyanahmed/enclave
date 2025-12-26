//! In-memory session storage.
//!
//! Suitable for development, testing, and single-instance deployments.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::AuthError;
use crate::crypto::generate_token;

use super::repository::SessionRepository;
use super::{Session, SessionData};

/// In-memory session storage.
///
/// Stores sessions in a `HashMap` protected by a `RwLock`.
/// Sessions are keyed by their session ID.
///
/// # Note
///
/// Sessions are lost when the process restarts.
/// For persistent storage, use [`FileSessionRepository`](super::FileSessionRepository).
#[derive(Clone)]
pub struct InMemorySessionRepository {
    sessions: Arc<RwLock<HashMap<String, SessionData>>>,
}

impl InMemorySessionRepository {
    /// Creates a new in-memory session repository.
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Returns the number of sessions currently stored.
    pub fn len(&self) -> usize {
        self.sessions.read().map(|guard| guard.len()).unwrap_or(0)
    }

    /// Returns true if there are no sessions stored.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for InMemorySessionRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SessionRepository for InMemorySessionRepository {
    async fn create(&self, data: SessionData) -> Result<String, AuthError> {
        let session_id = generate_token(32);

        self.sessions
            .write()
            .map_err(|_| AuthError::DatabaseError("Lock poisoned".to_owned()))?
            .insert(session_id.clone(), data);

        Ok(session_id)
    }

    async fn find(&self, session_id: &str) -> Result<Option<Session>, AuthError> {
        let sessions = self
            .sessions
            .read()
            .map_err(|_| AuthError::DatabaseError("Lock poisoned".to_owned()))?;

        Ok(sessions.get(session_id).map(|data| Session {
            id: session_id.to_owned(),
            data: data.clone(),
        }))
    }

    async fn extend(
        &self,
        session_id: &str,
        new_expires_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        if let Some(data) = self
            .sessions
            .write()
            .map_err(|_| AuthError::DatabaseError("Lock poisoned".to_owned()))?
            .get_mut(session_id)
        {
            data.expires_at = new_expires_at;
        }

        Ok(())
    }

    async fn destroy(&self, session_id: &str) -> Result<(), AuthError> {
        self.sessions
            .write()
            .map_err(|_| AuthError::DatabaseError("Lock poisoned".to_owned()))?
            .remove(session_id);

        Ok(())
    }

    async fn destroy_user_sessions(&self, user_id: i32) -> Result<(), AuthError> {
        self.sessions
            .write()
            .map_err(|_| AuthError::DatabaseError("Lock poisoned".to_owned()))?
            .retain(|_, data| data.user_id != user_id);

        Ok(())
    }

    #[allow(clippy::significant_drop_tightening)]
    async fn prune_expired(&self) -> Result<u64, AuthError> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| AuthError::DatabaseError("Lock poisoned".to_owned()))?;

        let now = Utc::now();
        let before_count = sessions.len();

        sessions.retain(|_, data| data.expires_at > now);

        let pruned = before_count.saturating_sub(sessions.len());
        Ok(u64::try_from(pruned).unwrap_or(u64::MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn create_test_session_data(user_id: i32) -> SessionData {
        SessionData {
            user_id,
            email: format!("user{user_id}@example.com"),
            name: format!("User {user_id}"),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(2),
        }
    }

    #[tokio::test]
    async fn test_create_and_find() {
        let repo = InMemorySessionRepository::new();
        let data = create_test_session_data(1);

        let session_id = repo.create(data.clone()).await.unwrap();
        assert_eq!(session_id.len(), 32);

        let found = repo.find(&session_id).await.unwrap();
        assert!(found.is_some());

        let session = found.unwrap();
        assert_eq!(session.id, session_id);
        assert_eq!(session.data.user_id, 1);
    }

    #[tokio::test]
    async fn test_find_nonexistent() {
        let repo = InMemorySessionRepository::new();

        let found = repo.find("nonexistent").await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_destroy() {
        let repo = InMemorySessionRepository::new();
        let data = create_test_session_data(1);

        let session_id = repo.create(data).await.unwrap();
        assert!(!repo.is_empty());

        repo.destroy(&session_id).await.unwrap();
        assert!(repo.is_empty());

        let found = repo.find(&session_id).await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_destroy_user_sessions() {
        let repo = InMemorySessionRepository::new();

        // Create multiple sessions for the same user
        repo.create(create_test_session_data(1)).await.unwrap();
        repo.create(create_test_session_data(1)).await.unwrap();
        repo.create(create_test_session_data(2)).await.unwrap();

        assert_eq!(repo.len(), 3);

        repo.destroy_user_sessions(1).await.unwrap();

        assert_eq!(repo.len(), 1);
    }

    #[tokio::test]
    async fn test_extend() {
        let repo = InMemorySessionRepository::new();
        let data = create_test_session_data(1);

        let session_id = repo.create(data).await.unwrap();

        let new_expires = Utc::now() + Duration::hours(5);
        repo.extend(&session_id, new_expires).await.unwrap();

        let session = repo.find(&session_id).await.unwrap().unwrap();
        assert_eq!(session.data.expires_at, new_expires);
    }

    #[tokio::test]
    async fn test_prune_expired() {
        let repo = InMemorySessionRepository::new();

        // Create expired session
        let expired_data = SessionData {
            user_id: 1,
            email: "expired@example.com".to_owned(),
            name: "Expired".to_owned(),
            created_at: Utc::now() - Duration::hours(3),
            expires_at: Utc::now() - Duration::hours(1),
        };
        repo.create(expired_data).await.unwrap();

        // Create valid session
        repo.create(create_test_session_data(2)).await.unwrap();

        assert_eq!(repo.len(), 2);

        let pruned = repo.prune_expired().await.unwrap();
        assert_eq!(pruned, 1);
        assert_eq!(repo.len(), 1);
    }
}
