use async_trait::async_trait;
use crate::AuthError;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct User {
    pub id: i32,
    pub email: String,
    pub name: String,
    pub hashed_password: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
impl User {
    pub fn mock() -> Self {
        let now = Utc::now();
        User {
            id: 1,
            email: "test@example.com".to_string(),
            name: "Test User".to_string(),
            hashed_password: "fakehashedpassword".to_string(),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn mock_from_credentials(email: &str, hashed_password: &str) -> Self {
        let now = Utc::now();
        User {
            id: 1,
            email: email.to_string(),
            name: "Test User".to_string(),
            hashed_password: hashed_password.to_string(),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn mock_from_email(email: &str) -> Self {
        let now = Utc::now();
        User {
            id: 1,
            email: email.to_string(),
            name: "Test User".to_string(),
            hashed_password: "fakehashedpassword".to_string(),
            created_at: now,
            updated_at: now,
        }
    }
}

#[async_trait]
pub trait UserRepository {
    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, AuthError>;

    async fn create_user(&self, email: &str, hashed_password: &str) -> Result<User, AuthError>;
}
