//! Server-side session authentication.
//!
//! This module provides session-based authentication using signed cookies.
//! Session data is stored server-side with pluggable storage backends.
//!
//! # Features
//!
//! - HMAC-SHA256 signed cookies (tamper-proof)
//! - Sliding window expiry
//! - Pluggable storage backends (file, in-memory, redis)
//!
//! # Example
//!
//! ```rust,ignore
//! use enclave::session::{InMemorySessionRepository, SessionConfig};
//! use enclave::SecretString;
//!
//! let session_repo = InMemorySessionRepository::new();
//! let session_config = SessionConfig {
//!     secret_key: SecretString::new("your-secret-key"),
//!     ..Default::default()
//! };
//! ```

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

/// Data stored in the session (server-side).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    /// User ID associated with this session.
    pub user_id: i32,
    /// User's email address.
    pub email: String,
    /// User's display name.
    pub name: String,
    /// When the session was created.
    pub created_at: DateTime<Utc>,
    /// When the session expires.
    pub expires_at: DateTime<Utc>,
}

/// A session with its ID and associated data.
#[derive(Debug, Clone)]
pub struct Session {
    /// Unique session identifier.
    pub id: String,
    /// Session data stored server-side.
    pub data: SessionData,
}

impl Session {
    /// Creates a new session with the given ID and data.
    pub fn new(id: String, data: SessionData) -> Self {
        Self { id, data }
    }

    /// Returns whether this session has expired.
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
