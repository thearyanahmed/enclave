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

#[cfg(test)]
mod tests {
    use crate::{ MockUserRepository, User};
    use super::*;
    use rand::rngs::OsRng;
    use argon2::{Argon2, PasswordHasher};
    use password_hash::SaltString;

    #[tokio::test]
    async fn test_login_action() {
        let repo = MockUserRepository::new();

        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        let password = "securepassword";

        // TODO: Separate password hashing logic into a utility function
        // We can extract this to a utility function in the future. The current impl doesn't help
        // as we are literally copy pasting the same code. 
        let hashed = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AuthError::Other(e.to_string()))
            .map(|hash| hash.to_string());

        let user = User::mock_from_credentials("user@email.com", hashed.unwrap().as_str());
        repo.users.lock().unwrap().push(user);

        let login = LoginAction::new(repo);
        let logged_in_user = login.execute("user@email.com", "securepassword").await;
        assert!(logged_in_user.is_ok());


        let failed_attempt = login.execute("user@email.com", "wrongpassword").await;
        assert!(failed_attempt.is_err());

        let failed_attempt = login.execute("wrong@email.com", "securepassword").await;
        assert!(failed_attempt.is_err());
    }
}
