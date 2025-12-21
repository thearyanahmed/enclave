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

#[derive(Debug, Clone)]
pub struct AccessToken {
    pub token: String,
    pub user_id: i32,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
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

#[async_trait]
pub trait TokenRepository {
    async fn create_token(&self, user_id: i32, expires_at: DateTime<Utc>) -> Result<AccessToken, AuthError>;

    async fn find_token(&self, token: &str) -> Result<Option<AccessToken>, AuthError>;

    async fn revoke_token(&self, token: &str) -> Result<(), AuthError>;

    async fn revoke_all_user_tokens(&self, user_id: i32) -> Result<(), AuthError>;
}


pub struct MockUserRepository {
    pub users: std::sync::Mutex<Vec<User>>,
}

#[cfg(test)]
impl MockUserRepository {
    pub fn new() -> Self {
        Self {
            users: std::sync::Mutex::new(vec![]),
        }
    }
}

#[cfg(test)]
#[async_trait]
impl UserRepository for MockUserRepository {
    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, AuthError> {
        let users = self.users.lock().unwrap();
        Ok(users.iter().find(|u| u.email == email).cloned())
    }

    async fn create_user(&self, email: &str, hashed_password: &str) -> Result<User, AuthError> {
        let mut users = self.users.lock().unwrap();

        let user = User::mock_from_credentials(email, hashed_password);

        users.push(user.clone());
        Ok(user)
    }
}
