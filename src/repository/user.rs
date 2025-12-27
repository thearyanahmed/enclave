use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::AuthError;

/// A user account in the authentication system.
///
/// This struct contains the core fields required for authentication. The
/// `hashed_password` field contains an Argon2 hash and is excluded from
/// serialization to prevent accidental exposure.
///
/// # Required Fields
///
/// When implementing [`UserRepository`], your database schema must include:
///
/// | Field | Type | Description |
/// |-------|------|-------------|
/// | `id` | `i32` | Unique identifier |
/// | `email` | `String` | User's email (used for login) |
/// | `name` | `String` | Display name |
/// | `hashed_password` | `String` | Argon2 password hash |
/// | `email_verified_at` | `Option<DateTime<Utc>>` | When email was verified |
/// | `created_at` | `DateTime<Utc>` | Creation timestamp |
/// | `updated_at` | `DateTime<Utc>` | Last update timestamp |
///
/// # Extending with Custom Fields
///
/// If you need additional fields (avatar, phone, etc.), use composition:
///
/// ```rust,ignore
/// struct AppUser {
///     auth: enclave::AuthUser,
///     avatar_url: Option<String>,
///     stripe_id: Option<String>,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUser {
    pub id: i32,
    pub email: String,
    pub name: String,
    #[serde(skip_serializing)]
    pub hashed_password: String,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AuthUser {
    /// Returns whether the user's email is verified.
    pub fn is_email_verified(&self) -> bool {
        self.email_verified_at.is_some()
    }
}

#[cfg(any(test, feature = "mocks"))]
impl AuthUser {
    pub fn mock() -> Self {
        let now = Utc::now();
        AuthUser {
            id: 1,
            email: "test@example.com".to_owned(),
            name: "Test User".to_owned(),
            hashed_password: "fakehashedpassword".to_owned(),
            email_verified_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn mock_from_credentials(email: &str, hashed_password: &str) -> Self {
        let now = Utc::now();
        AuthUser {
            id: 1,
            email: email.to_owned(),
            name: "Test User".to_owned(),
            hashed_password: hashed_password.to_owned(),
            email_verified_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn mock_from_email(email: &str) -> Self {
        let now = Utc::now();
        AuthUser {
            id: 1,
            email: email.to_owned(),
            name: "Test User".to_owned(),
            hashed_password: "fakehashedpassword".to_owned(),
            email_verified_at: None,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Storage abstraction for user accounts.
///
/// Implement this trait to provide user persistence. See `PostgresUserRepository`
/// for a production implementation or `MockUserRepository` for testing.
#[async_trait]
pub trait UserRepository {
    async fn find_user_by_id(&self, id: i32) -> Result<Option<AuthUser>, AuthError>;
    async fn find_user_by_email(&self, email: &str) -> Result<Option<AuthUser>, AuthError>;
    async fn create_user(&self, email: &str, hashed_password: &str) -> Result<AuthUser, AuthError>;
    async fn update_password(&self, user_id: i32, hashed_password: &str) -> Result<(), AuthError>;
    /// Sets `email_verified_at` to the current timestamp.
    async fn verify_email(&self, user_id: i32) -> Result<(), AuthError>;
    async fn update_user(
        &self,
        user_id: i32,
        name: &str,
        email: &str,
    ) -> Result<AuthUser, AuthError>;
    async fn delete_user(&self, user_id: i32) -> Result<(), AuthError>;
}
