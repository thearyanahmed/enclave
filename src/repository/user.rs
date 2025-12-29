use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::AuthError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUser {
    pub id: i64,
    pub email: String,
    pub name: String,
    #[serde(skip_serializing)]
    pub hashed_password: String,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AuthUser {
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

#[async_trait]
pub trait UserRepository {
    async fn find_user_by_id(&self, id: i64) -> Result<Option<AuthUser>, AuthError>;
    async fn find_user_by_email(&self, email: &str) -> Result<Option<AuthUser>, AuthError>;
    async fn create_user(&self, email: &str, hashed_password: &str) -> Result<AuthUser, AuthError>;
    async fn update_password(&self, user_id: i64, hashed_password: &str) -> Result<(), AuthError>;
    async fn verify_email(&self, user_id: i64) -> Result<(), AuthError>;
    async fn update_user(
        &self,
        user_id: i64,
        name: &str,
        email: &str,
    ) -> Result<AuthUser, AuthError>;
    async fn delete_user(&self, user_id: i64) -> Result<(), AuthError>;
}
