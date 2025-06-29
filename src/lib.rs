use async_trait::async_trait;

pub enum AuthError {
    Other(String),
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

