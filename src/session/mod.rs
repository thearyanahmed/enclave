mod config;
mod cookie;
mod file_store;
mod memory_store;
mod repository;

use chrono::{DateTime, Utc};
pub use config::{SameSite, SessionConfig};
pub use cookie::{sign_session_id, verify_signed_cookie};
pub use file_store::FileSessionRepository;
pub use memory_store::InMemorySessionRepository;
pub use repository::SessionRepository;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    pub user_id: i64,
    pub email: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub data: SessionData,
}

impl Session {
    pub fn new(id: String, data: SessionData) -> Self {
        Self { id, data }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.data.expires_at
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    #[test]
    fn test_session_not_expired() {
        let data = SessionData {
            user_id: 1,
            email: "test@example.com".to_owned(),
            name: "Test User".to_owned(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
        };
        let session = Session::new("session123".to_owned(), data);
        assert!(!session.is_expired());
    }

    #[test]
    fn test_session_expired() {
        let data = SessionData {
            user_id: 1,
            email: "test@example.com".to_owned(),
            name: "Test User".to_owned(),
            created_at: Utc::now() - Duration::hours(3),
            expires_at: Utc::now() - Duration::hours(1),
        };
        let session = Session::new("session123".to_owned(), data);
        assert!(session.is_expired());
    }
}
