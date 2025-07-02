
use async_trait::async_trait;
use crate::AuthError;

#[async_trait]
pub trait UserRepository {
    type User: Send + Sync;

    async fn find_user_by_email(&self, email: &str) -> Result<Option<Self::User>, AuthError>;

    async fn create_user(&self, email: &str, hashed_password: &str) -> Result<Self::User, AuthError>;
}
