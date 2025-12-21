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

pub struct MockTokenRepository {
    pub tokens: std::sync::Mutex<Vec<AccessToken>>,
}

#[cfg(test)]
impl MockTokenRepository {
    pub fn new() -> Self {
        Self {
            tokens: std::sync::Mutex::new(vec![]),
        }
    }

    fn generate_token() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..32)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect()
    }
}

#[cfg(test)]
#[async_trait]
impl TokenRepository for MockTokenRepository {
    async fn create_token(&self, user_id: i32, expires_at: DateTime<Utc>) -> Result<AccessToken, AuthError> {
        let mut tokens = self.tokens.lock().unwrap();
        let token = AccessToken {
            token: Self::generate_token(),
            user_id,
            expires_at,
            created_at: Utc::now(),
        };
        tokens.push(token.clone());
        Ok(token)
    }

    async fn find_token(&self, token: &str) -> Result<Option<AccessToken>, AuthError> {
        let tokens = self.tokens.lock().unwrap();
        Ok(tokens.iter().find(|t| t.token == token).cloned())
    }

    async fn revoke_token(&self, token: &str) -> Result<(), AuthError> {
        let mut tokens = self.tokens.lock().unwrap();
        tokens.retain(|t| t.token != token);
        Ok(())
    }

    async fn revoke_all_user_tokens(&self, user_id: i32) -> Result<(), AuthError> {
        let mut tokens = self.tokens.lock().unwrap();
        tokens.retain(|t| t.user_id != user_id);
        Ok(())
    }
}
