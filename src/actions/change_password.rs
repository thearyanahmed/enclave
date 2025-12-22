use crate::validators::validate_password;
use crate::{AuthError, UserRepository};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use password_hash::{PasswordHash, SaltString};
use rand::rngs::OsRng;

pub struct ChangePasswordAction<U: UserRepository> {
    user_repository: U,
}

impl<U: UserRepository> ChangePasswordAction<U> {
    pub fn new(user_repository: U) -> Self {
        ChangePasswordAction { user_repository }
    }

    pub async fn execute(
        &self,
        user_id: i32,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), AuthError> {
        let user = self.user_repository.find_user_by_id(user_id).await?;

        match user {
            Some(user) => {
                if !verify_password(current_password, &user.hashed_password)? {
                    return Err(AuthError::InvalidCredentials);
                }

                validate_password(new_password)?;

                let hashed = hash_password(new_password)?;
                self.user_repository.update_password(user_id, &hashed).await
            }
            None => Err(AuthError::UserNotFound),
        }
    }
}

fn verify_password(password: &str, hashed: &str) -> Result<bool, AuthError> {
    let parsed_hash = PasswordHash::new(hashed).map_err(|_| AuthError::PasswordHashError)?;
    match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
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
    use crate::validators::ValidationError;
    use crate::{MockUserRepository, User};

    fn create_user_with_password(email: &str, password: &str) -> User {
        let hashed = hash_password(password).unwrap();
        User::mock_from_credentials(email, &hashed)
    }

    #[tokio::test]
    async fn test_change_password_success() {
        let user_repo = MockUserRepository::new();

        let user = create_user_with_password("user@example.com", "oldpassword");
        let user_id = user.id;
        user_repo.users.lock().unwrap().push(user);

        let action = ChangePasswordAction::new(user_repo);
        let result = action.execute(user_id, "oldpassword", "newpassword").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_change_password_wrong_current() {
        let user_repo = MockUserRepository::new();

        let user = create_user_with_password("user@example.com", "oldpassword");
        let user_id = user.id;
        user_repo.users.lock().unwrap().push(user);

        let action = ChangePasswordAction::new(user_repo);
        let result = action
            .execute(user_id, "wrongpassword", "newpassword")
            .await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::InvalidCredentials);
    }

    #[tokio::test]
    async fn test_change_password_user_not_found() {
        let user_repo = MockUserRepository::new();

        let action = ChangePasswordAction::new(user_repo);
        let result = action.execute(999, "old", "new").await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::UserNotFound);
    }

    #[tokio::test]
    async fn test_change_password_invalid_new_password() {
        let user_repo = MockUserRepository::new();

        let user = create_user_with_password("user@example.com", "oldpassword");
        let user_id = user.id;
        user_repo.users.lock().unwrap().push(user);

        let action = ChangePasswordAction::new(user_repo);
        let result = action.execute(user_id, "oldpassword", "short").await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            AuthError::Validation(ValidationError::PasswordTooShort)
        );
    }
}
