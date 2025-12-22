use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::AuthError;

/// A user account in the authentication system.
///
/// The `hashed_password` field contains an Argon2 hash and should never be exposed to clients.
/// Use `email_verified_at` to check if the user has confirmed their email address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: i32,
    pub email: String,
    pub name: String,
    #[serde(skip_serializing)]
    pub hashed_password: String,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[cfg(any(test, feature = "mocks"))]
impl User {
    pub fn mock() -> Self {
        let now = Utc::now();
        User {
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
        User {
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
        User {
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
    async fn find_user_by_id(&self, id: i32) -> Result<Option<User>, AuthError>;
    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, AuthError>;
    async fn create_user(&self, email: &str, hashed_password: &str) -> Result<User, AuthError>;
    async fn update_password(&self, user_id: i32, hashed_password: &str) -> Result<(), AuthError>;
    /// Sets `email_verified_at` to the current timestamp.
    async fn verify_email(&self, user_id: i32) -> Result<(), AuthError>;
    async fn update_user(&self, user_id: i32, name: &str, email: &str) -> Result<User, AuthError>;
    async fn delete_user(&self, user_id: i32) -> Result<(), AuthError>;
}
