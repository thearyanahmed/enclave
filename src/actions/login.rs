use crate::{UserRepository, AuthError};
pub struct LoginAction<R: UserRepository> {
    repository: R,
}

impl<R: UserRepository> LoginAction<R> {
    pub fn new(repository: R) -> Self {
        LoginAction { repository }
    }

    pub async fn execute(&self, email: &str, password: &str) -> Result<bool, AuthError> {
        let user = self.repository.find_user_by_email(email).await?;
        if let Some(user) = user {
            if verify_password(password, &user.hashed_password)? {
                return Ok(true);
            }
        }
        Err(AuthError::Other("Invalid email or password".to_string()))
    }
}

fn verify_password(password: &str, hashed: &str) -> Result<bool, AuthError> {
    use argon2::{Argon2, PasswordVerifier};
    use password_hash::PasswordHash;

    let parsed_hash = PasswordHash::new(hashed).map_err(|e| AuthError::Other(e.to_string()))?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map(|_| true)
        .map_err(|e| AuthError::Other(e.to_string()))
}

