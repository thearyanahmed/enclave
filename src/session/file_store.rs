//! File-based session storage.
//!
//! Stores sessions as JSON files in a directory.

use std::path::PathBuf;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::repository::SessionRepository;
use super::{Session, SessionData};
use crate::AuthError;
use crate::crypto::generate_token;

/// File-based session storage.
///
/// Each session is stored as a JSON file named `{session_id}.json`
/// in the configured directory.
///
/// # Example
///
/// ```rust,ignore
/// use enclave::session::FileSessionRepository;
///
/// let repo = FileSessionRepository::new("/var/lib/myapp/sessions")?;
/// ```
pub struct FileSessionRepository {
    directory: PathBuf,
}

impl FileSessionRepository {
    /// Creates a new file session repository.
    ///
    /// Creates the directory if it doesn't exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created.
    pub fn new(directory: impl Into<PathBuf>) -> Result<Self, AuthError> {
        let dir = directory.into();
        std::fs::create_dir_all(&dir).map_err(|e| {
            AuthError::DatabaseError(format!("Failed to create session directory: {e}"))
        })?;
        Ok(Self { directory: dir })
    }

    /// Returns the path for a session file.
    fn session_path(&self, session_id: &str) -> PathBuf {
        self.directory.join(format!("{session_id}.json"))
    }

    /// Reads session data from a file.
    fn read_session(&self, session_id: &str) -> Result<Option<SessionData>, AuthError> {
        let path = self.session_path(session_id);

        if !path.exists() {
            return Ok(None);
        }

        let content = std::fs::read_to_string(&path)
            .map_err(|e| AuthError::DatabaseError(format!("Failed to read session file: {e}")))?;

        let data: SessionData = serde_json::from_str(&content)
            .map_err(|e| AuthError::DatabaseError(format!("Failed to parse session file: {e}")))?;

        Ok(Some(data))
    }

    /// Writes session data to a file.
    fn write_session(&self, session_id: &str, data: &SessionData) -> Result<(), AuthError> {
        let path = self.session_path(session_id);

        let content = serde_json::to_string_pretty(data)
            .map_err(|e| AuthError::DatabaseError(format!("Failed to serialize session: {e}")))?;

        std::fs::write(&path, content)
            .map_err(|e| AuthError::DatabaseError(format!("Failed to write session file: {e}")))?;

        Ok(())
    }
}

#[async_trait]
impl SessionRepository for FileSessionRepository {
    async fn create(&self, data: SessionData) -> Result<String, AuthError> {
        let session_id = generate_token(32);
        self.write_session(&session_id, &data)?;
        Ok(session_id)
    }

    async fn find(&self, session_id: &str) -> Result<Option<Session>, AuthError> {
        // Validate session_id to prevent path traversal
        if !session_id.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Ok(None);
        }

        Ok(self.read_session(session_id)?.map(|data| Session {
            id: session_id.to_owned(),
            data,
        }))
    }

    async fn extend(
        &self,
        session_id: &str,
        new_expires_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        // Validate session_id to prevent path traversal
        if !session_id.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Ok(());
        }

        if let Some(mut data) = self.read_session(session_id)? {
            data.expires_at = new_expires_at;
            self.write_session(session_id, &data)?;
        }

        Ok(())
    }

    async fn destroy(&self, session_id: &str) -> Result<(), AuthError> {
        // Validate session_id to prevent path traversal
        if !session_id.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Ok(());
        }

        let path = self.session_path(session_id);
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| {
                AuthError::DatabaseError(format!("Failed to delete session file: {e}"))
            })?;
        }

        Ok(())
    }

    async fn destroy_user_sessions(&self, user_id: i32) -> Result<(), AuthError> {
        let entries = std::fs::read_dir(&self.directory).map_err(|e| {
            AuthError::DatabaseError(format!("Failed to read session directory: {e}"))
        })?;

        for entry in entries.flatten() {
            let path = entry.path();

            if path.extension().is_some_and(|ext| ext == "json") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(data) = serde_json::from_str::<SessionData>(&content) {
                        if data.user_id == user_id {
                            let _ = std::fs::remove_file(&path);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn prune_expired(&self) -> Result<u64, AuthError> {
        let entries = std::fs::read_dir(&self.directory).map_err(|e| {
            AuthError::DatabaseError(format!("Failed to read session directory: {e}"))
        })?;

        let now = Utc::now();
        let mut pruned = 0u64;

        for entry in entries.flatten() {
            let path = entry.path();

            if path.extension().is_some_and(|ext| ext == "json") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(data) = serde_json::from_str::<SessionData>(&content) {
                        if data.expires_at <= now && std::fs::remove_file(&path).is_ok() {
                            pruned += 1;
                        }
                    }
                }
            }
        }

        Ok(pruned)
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use chrono::Duration;

    use super::*;

    fn create_test_session_data(user_id: i32) -> SessionData {
        SessionData {
            user_id,
            email: format!("user{user_id}@example.com"),
            name: format!("User {user_id}"),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(2),
        }
    }

    fn temp_dir() -> PathBuf {
        let dir = env::temp_dir().join(format!("enclave_sessions_test_{}", generate_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cleanup(dir: &PathBuf) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn test_create_and_find() {
        let dir = temp_dir();
        let repo = FileSessionRepository::new(&dir).unwrap();
        let data = create_test_session_data(1);

        let session_id = repo.create(data.clone()).await.unwrap();
        assert_eq!(session_id.len(), 32);

        let found = repo.find(&session_id).await.unwrap();
        assert!(found.is_some());

        let session = found.unwrap();
        assert_eq!(session.id, session_id);
        assert_eq!(session.data.user_id, 1);

        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_find_nonexistent() {
        let dir = temp_dir();
        let repo = FileSessionRepository::new(&dir).unwrap();

        let found = repo.find("nonexistent").await.unwrap();
        assert!(found.is_none());

        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_path_traversal_prevention() {
        let dir = temp_dir();
        let repo = FileSessionRepository::new(&dir).unwrap();

        // These should be rejected
        let found = repo.find("../etc/passwd").await.unwrap();
        assert!(found.is_none());

        let found = repo.find("session/../../../etc/passwd").await.unwrap();
        assert!(found.is_none());

        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_destroy() {
        let dir = temp_dir();
        let repo = FileSessionRepository::new(&dir).unwrap();
        let data = create_test_session_data(1);

        let session_id = repo.create(data).await.unwrap();
        assert!(repo.session_path(&session_id).exists());

        repo.destroy(&session_id).await.unwrap();
        assert!(!repo.session_path(&session_id).exists());

        let found = repo.find(&session_id).await.unwrap();
        assert!(found.is_none());

        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_extend() {
        let dir = temp_dir();
        let repo = FileSessionRepository::new(&dir).unwrap();
        let data = create_test_session_data(1);

        let session_id = repo.create(data).await.unwrap();

        let new_expires = Utc::now() + Duration::hours(5);
        repo.extend(&session_id, new_expires).await.unwrap();

        let session = repo.find(&session_id).await.unwrap().unwrap();
        assert_eq!(session.data.expires_at, new_expires);

        cleanup(&dir);
    }
}
