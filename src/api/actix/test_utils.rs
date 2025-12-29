use actix_web::test::TestRequest;
use chrono::{Duration, Utc};

use crate::{
    AccessToken, Argon2Hasher, AuthError, AuthUser, PasswordHasher, StatefulTokenRepository,
    UserRepository,
};

pub struct TestUserBuilder<'a, U, T> {
    user_repo: &'a U,
    token_repo: &'a T,
    email: String,
    password: String,
    name: Option<String>,
    token_expiry: Duration,
}

impl<'a, U, T> TestUserBuilder<'a, U, T>
where
    U: UserRepository,
    T: StatefulTokenRepository,
{
    pub fn new(user_repo: &'a U, token_repo: &'a T) -> Self {
        Self {
            user_repo,
            token_repo,
            email: format!("test-{}@example.com", uuid()),
            password: "testpassword123".to_owned(),
            name: None,
            token_expiry: Duration::hours(1),
        }
    }

    #[must_use]
    pub fn email(mut self, email: impl Into<String>) -> Self {
        self.email = email.into();
        self
    }

    #[must_use]
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.password = password.into();
        self
    }

    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    #[must_use]
    pub fn token_expiry(mut self, duration: Duration) -> Self {
        self.token_expiry = duration;
        self
    }

    pub async fn build(self) -> Result<(AuthUser, AccessToken), AuthError> {
        let hasher = Argon2Hasher::default();
        let hashed_password = hasher.hash(&self.password)?;

        let user = self
            .user_repo
            .create_user(&self.email, &hashed_password)
            .await?;

        // Update name if provided
        let user = if let Some(name) = self.name {
            self.user_repo
                .update_user(user.id, &name, &user.email)
                .await?
        } else {
            user
        };

        let expires_at = Utc::now() + self.token_expiry;
        let token = self.token_repo.create_token(user.id, expires_at).await?;

        Ok((user, token))
    }
}

pub trait ActingAs {
    #[must_use]
    fn acting_as(self, token: &AccessToken) -> Self;
}

impl ActingAs for TestRequest {
    fn acting_as(self, token: &AccessToken) -> Self {
        self.insert_header((
            "Authorization",
            format!("Bearer {}", token.token.expose_secret()),
        ))
    }
}

fn uuid() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    format!("{}{}", duration.as_nanos(), rand_suffix())
}

fn rand_suffix() -> String {
    crate::crypto::generate_token(8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MockTokenRepository, MockUserRepository};

    #[tokio::test]
    async fn test_user_builder_creates_user_and_token() {
        let user_repo = MockUserRepository::new();
        let token_repo = MockTokenRepository::new();

        let (user, token) = TestUserBuilder::new(&user_repo, &token_repo)
            .email("builder@example.com")
            .password("password123")
            .build()
            .await
            .unwrap();

        assert_eq!(user.email, "builder@example.com");
        assert_eq!(token.user_id, user.id);
        assert!(!token.token.expose_secret().is_empty());
    }

    #[tokio::test]
    async fn test_user_builder_with_name() {
        let user_repo = MockUserRepository::new();
        let token_repo = MockTokenRepository::new();

        let (user, _token) = TestUserBuilder::new(&user_repo, &token_repo)
            .email("named@example.com")
            .name("Test User")
            .build()
            .await
            .unwrap();

        assert_eq!(user.name, "Test User");
    }

    #[tokio::test]
    async fn test_user_builder_default_values() {
        let user_repo = MockUserRepository::new();
        let token_repo = MockTokenRepository::new();

        let (user, token) = TestUserBuilder::new(&user_repo, &token_repo)
            .build()
            .await
            .unwrap();

        assert!(user.email.contains("@example.com"));
        assert!(token.expires_at > Utc::now());
    }
}
