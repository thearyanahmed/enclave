pub mod actions;
use async_trait::async_trait;
use std::fmt;

#[derive(Debug)]
pub enum AuthError {
    Other(String),
}

impl std::error::Error for AuthError {}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

#[async_trait]
pub trait UserRepository {
    type User: Send + Sync;

    // Find a user by their unique identifier.
    async fn find_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<Self::User>, AuthError>;


    async fn create_user(
        &self,
        email: &str,
        hashed_password: &str,
    ) -> Result<Self::User, AuthError>;
}

