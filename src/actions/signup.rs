use crate::{UserRepository, AuthError, User};
use argon2::{Argon2, PasswordHasher};
use password_hash::SaltString;
use rand::rngs::OsRng;

pub struct SignupAction<R> {
    repository: R,
}

impl<R: UserRepository> SignupAction<R> {
    pub fn new(repository: R) -> Self {
        SignupAction { repository }
    }

    pub async fn execute(&self, email: &str, password: &str) -> Result<User, AuthError> {
        if let Some(_) = self.repository.find_user_by_email(email).await? {
            return Err(AuthError::UserAlreadyExists);
        }

        let hashed = hash_password(password)?;
        self.repository.create_user(email, &hashed).await
    }
}

fn hash_password(password: &str) -> Result<String, AuthError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| AuthError::PasswordHashError)
        .map(|hash| hash.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockUserRepository;

    #[tokio::test]
    async fn test_signup_success() {
        let repo = MockUserRepository::new();
        let signup = SignupAction::new(repo);

        let result = signup
            .execute("user@example.com", "securepassword")
            .await;

        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.email, "user@example.com");
    }

    #[tokio::test]
    async fn test_signup_user_already_exists() {
        let existing_user = User::mock();

        let repo = MockUserRepository {
            users: std::sync::Mutex::new(vec![existing_user]),
        };

        let signup = SignupAction::new(repo);
        // add an user
        _ = signup
            .execute("user@example.com", "newpassword")
            .await;

        let result = signup
            .execute("user@example.com", "newpassword")
            .await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::UserAlreadyExists);
    }
}

