//! Test utilities for actix-web integration testing.
//!
//! Provides helpers to simplify testing authenticated endpoints.
//!
//! # Example
//!
//! ```ignore
//! use enclave::api::actix::test_utils::{TestUserBuilder, ActingAs};
//!
//! let (user, token) = TestUserBuilder::new(&user_repo, &token_repo)
//!     .email("test@example.com")
//!     .password("password123")
//!     .build()
//!     .await?;
//!
//! let req = test::TestRequest::get()
//!     .uri("/auth/me")
//!     .acting_as(&token)
//!     .to_request();
//! ```

use actix_web::test::TestRequest;
use chrono::{Duration, Utc};

use crate::{
    AccessToken, Argon2Hasher, AuthError, PasswordHasher, StatefulTokenRepository, User,
    UserRepository,
};

/// Builder for creating test users with associated tokens.
///
/// This simplifies test setup by handling user creation and token generation
/// in a single fluent interface.
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
    /// Creates a new test user builder with default values.
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

    /// Sets the email for the test user.
    #[must_use]
    pub fn email(mut self, email: impl Into<String>) -> Self {
        self.email = email.into();
        self
    }

    /// Sets the password for the test user.
    #[must_use]
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.password = password.into();
        self
    }

    /// Sets the name for the test user.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the token expiry duration.
    #[must_use]
    pub fn token_expiry(mut self, duration: Duration) -> Self {
        self.token_expiry = duration;
        self
    }

    /// Creates the test user and returns the user with a valid access token.
    ///
    /// # Errors
    ///
    /// Returns an error if user creation or token generation fails.
    pub async fn build(self) -> Result<(User, AccessToken), AuthError> {
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

/// Extension trait for adding authentication to test requests.
///
/// Adds the `acting_as` method to `TestRequest` for easy authentication.
pub trait ActingAs {
    /// Adds an Authorization header with the given token.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let req = test::TestRequest::get()
    ///     .uri("/auth/me")
    ///     .acting_as(&token)
    ///     .to_request();
    /// ```
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

/// Generates a simple unique identifier for test isolation.
fn uuid() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    format!("{}{}", duration.as_nanos(), rand_suffix())
}

fn rand_suffix() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..8)
        .map(|_| char::from(rng.sample(rand::distributions::Alphanumeric)))
        .collect()
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
