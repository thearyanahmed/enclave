use async_trait::async_trait;
use crate::AuthError;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct User {
    pub id: i32,
    pub email: String,
    pub name: String,
    pub hashed_password: String,
    pub email_verified_at: Option<DateTime<Utc>>,
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

#[derive(Debug, Clone)]
pub struct PasswordResetToken {
    pub token: String,
    pub user_id: i32,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct EmailVerificationToken {
    pub token: String,
    pub user_id: i32,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct LoginAttempt {
    pub email: String,
    pub success: bool,
    pub ip_address: Option<String>,
    pub attempted_at: DateTime<Utc>,
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
            email_verified_at: None,
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
            email_verified_at: None,
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
            email_verified_at: None,
            created_at: now,
            updated_at: now,
        }
    }
}

#[async_trait]
pub trait UserRepository {
    async fn find_user_by_id(&self, id: i32) -> Result<Option<User>, AuthError>;

    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, AuthError>;

    async fn create_user(&self, email: &str, hashed_password: &str) -> Result<User, AuthError>;

    async fn update_password(&self, user_id: i32, hashed_password: &str) -> Result<(), AuthError>;

    async fn verify_email(&self, user_id: i32) -> Result<(), AuthError>;

    async fn update_user(&self, user_id: i32, name: &str, email: &str) -> Result<User, AuthError>;

    async fn delete_user(&self, user_id: i32) -> Result<(), AuthError>;
}

#[async_trait]
pub trait TokenRepository {
    async fn create_token(&self, user_id: i32, expires_at: DateTime<Utc>) -> Result<AccessToken, AuthError>;

    async fn find_token(&self, token: &str) -> Result<Option<AccessToken>, AuthError>;

    async fn revoke_token(&self, token: &str) -> Result<(), AuthError>;

    async fn revoke_all_user_tokens(&self, user_id: i32) -> Result<(), AuthError>;
}

#[async_trait]
pub trait PasswordResetRepository {
    async fn create_reset_token(&self, user_id: i32, expires_at: DateTime<Utc>) -> Result<PasswordResetToken, AuthError>;

    async fn find_reset_token(&self, token: &str) -> Result<Option<PasswordResetToken>, AuthError>;

    async fn delete_reset_token(&self, token: &str) -> Result<(), AuthError>;
}

#[async_trait]
pub trait EmailVerificationRepository {
    async fn create_verification_token(&self, user_id: i32, expires_at: DateTime<Utc>) -> Result<EmailVerificationToken, AuthError>;

    async fn find_verification_token(&self, token: &str) -> Result<Option<EmailVerificationToken>, AuthError>;

    async fn delete_verification_token(&self, token: &str) -> Result<(), AuthError>;
}

#[async_trait]
pub trait RateLimiterRepository {
    async fn record_attempt(&self, email: &str, success: bool, ip_address: Option<&str>) -> Result<(), AuthError>;

    async fn get_recent_failed_attempts(&self, email: &str, since: DateTime<Utc>) -> Result<u32, AuthError>;

    async fn clear_attempts(&self, email: &str) -> Result<(), AuthError>;
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
    async fn find_user_by_id(&self, id: i32) -> Result<Option<User>, AuthError> {
        let users = self.users.lock().unwrap();
        Ok(users.iter().find(|u| u.id == id).cloned())
    }

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

    async fn update_password(&self, user_id: i32, hashed_password: &str) -> Result<(), AuthError> {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.iter_mut().find(|u| u.id == user_id) {
            user.hashed_password = hashed_password.to_string();
            user.updated_at = Utc::now();
            Ok(())
        } else {
            Err(AuthError::UserNotFound)
        }
    }

    async fn verify_email(&self, user_id: i32) -> Result<(), AuthError> {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.iter_mut().find(|u| u.id == user_id) {
            user.email_verified_at = Some(Utc::now());
            user.updated_at = Utc::now();
            Ok(())
        } else {
            Err(AuthError::UserNotFound)
        }
    }

    async fn update_user(&self, user_id: i32, name: &str, email: &str) -> Result<User, AuthError> {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.iter_mut().find(|u| u.id == user_id) {
            user.name = name.to_string();
            user.email = email.to_string();
            user.updated_at = Utc::now();
            Ok(user.clone())
        } else {
            Err(AuthError::UserNotFound)
        }
    }

    async fn delete_user(&self, user_id: i32) -> Result<(), AuthError> {
        let mut users = self.users.lock().unwrap();
        let len_before = users.len();
        users.retain(|u| u.id != user_id);
        if users.len() < len_before {
            Ok(())
        } else {
            Err(AuthError::UserNotFound)
        }
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

pub struct MockPasswordResetRepository {
    pub tokens: std::sync::Mutex<Vec<PasswordResetToken>>,
}

#[cfg(test)]
impl MockPasswordResetRepository {
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
impl PasswordResetRepository for MockPasswordResetRepository {
    async fn create_reset_token(&self, user_id: i32, expires_at: DateTime<Utc>) -> Result<PasswordResetToken, AuthError> {
        let mut tokens = self.tokens.lock().unwrap();
        let token = PasswordResetToken {
            token: Self::generate_token(),
            user_id,
            expires_at,
            created_at: Utc::now(),
        };
        tokens.push(token.clone());
        Ok(token)
    }

    async fn find_reset_token(&self, token: &str) -> Result<Option<PasswordResetToken>, AuthError> {
        let tokens = self.tokens.lock().unwrap();
        Ok(tokens.iter().find(|t| t.token == token).cloned())
    }

    async fn delete_reset_token(&self, token: &str) -> Result<(), AuthError> {
        let mut tokens = self.tokens.lock().unwrap();
        tokens.retain(|t| t.token != token);
        Ok(())
    }
}

pub struct MockEmailVerificationRepository {
    pub tokens: std::sync::Mutex<Vec<EmailVerificationToken>>,
}

#[cfg(test)]
impl MockEmailVerificationRepository {
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
impl EmailVerificationRepository for MockEmailVerificationRepository {
    async fn create_verification_token(&self, user_id: i32, expires_at: DateTime<Utc>) -> Result<EmailVerificationToken, AuthError> {
        let mut tokens = self.tokens.lock().unwrap();
        let token = EmailVerificationToken {
            token: Self::generate_token(),
            user_id,
            expires_at,
            created_at: Utc::now(),
        };
        tokens.push(token.clone());
        Ok(token)
    }

    async fn find_verification_token(&self, token: &str) -> Result<Option<EmailVerificationToken>, AuthError> {
        let tokens = self.tokens.lock().unwrap();
        Ok(tokens.iter().find(|t| t.token == token).cloned())
    }

    async fn delete_verification_token(&self, token: &str) -> Result<(), AuthError> {
        let mut tokens = self.tokens.lock().unwrap();
        tokens.retain(|t| t.token != token);
        Ok(())
    }
}

pub struct MockRateLimiterRepository {
    pub attempts: std::sync::Mutex<Vec<LoginAttempt>>,
}

#[cfg(test)]
impl MockRateLimiterRepository {
    pub fn new() -> Self {
        Self {
            attempts: std::sync::Mutex::new(vec![]),
        }
    }
}

#[cfg(test)]
#[async_trait]
impl RateLimiterRepository for MockRateLimiterRepository {
    async fn record_attempt(&self, email: &str, success: bool, ip_address: Option<&str>) -> Result<(), AuthError> {
        let mut attempts = self.attempts.lock().unwrap();
        attempts.push(LoginAttempt {
            email: email.to_string(),
            success,
            ip_address: ip_address.map(|s| s.to_string()),
            attempted_at: Utc::now(),
        });
        Ok(())
    }

    async fn get_recent_failed_attempts(&self, email: &str, since: DateTime<Utc>) -> Result<u32, AuthError> {
        let attempts = self.attempts.lock().unwrap();
        let count = attempts
            .iter()
            .filter(|a| a.email == email && !a.success && a.attempted_at >= since)
            .count() as u32;
        Ok(count)
    }

    async fn clear_attempts(&self, email: &str) -> Result<(), AuthError> {
        let mut attempts = self.attempts.lock().unwrap();
        attempts.retain(|a| a.email != email);
        Ok(())
    }
}
