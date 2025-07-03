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
            return Err(AuthError::Other("User already exists".to_string()));
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
        .map_err(|e| AuthError::Other(e.to_string()))
        .map(|hash| hash.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    pub struct MockRepo {
        users: std::sync::Mutex<Vec<User>>,
    }

    impl MockRepo {
        pub fn new() -> Self {
            Self {
                users: std::sync::Mutex::new(vec![]),
            }
        }
    }

    #[async_trait]
    impl UserRepository for MockRepo {

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

    #[tokio::test]
    async fn test_signup_success() {
        let repo = MockRepo::new();
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

        let repo = MockRepo {
            users: std::sync::Mutex::new(vec![existing_user]),
        };

        let signup = SignupAction::new(repo);
        let result = signup
            .execute("user@example.com", "newpassword")
            .await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            AuthError::Other("User already exists".into()).to_string()
        );
    }
}

