use crate::crypto::{Argon2Hasher, PasswordHasher, SecretString};
use crate::validators::PasswordPolicy;
use crate::{AuthError, UserRepository};

pub struct ChangePasswordAction<U, H = Argon2Hasher>
where
    U: UserRepository,
{
    user_repository: U,
    password_policy: PasswordPolicy,
    hasher: H,
}

impl<U: UserRepository> ChangePasswordAction<U, Argon2Hasher> {
    /// Creates a new `ChangePasswordAction` with the default password policy and hasher.
    pub fn new(user_repository: U) -> Self {
        Self {
            user_repository,
            password_policy: PasswordPolicy::default(),
            hasher: Argon2Hasher::default(),
        }
    }

    /// Creates a new `ChangePasswordAction` with a custom password policy.
    pub fn with_policy(user_repository: U, password_policy: PasswordPolicy) -> Self {
        Self {
            user_repository,
            password_policy,
            hasher: Argon2Hasher::default(),
        }
    }
}

impl<U: UserRepository, H: PasswordHasher> ChangePasswordAction<U, H> {
    /// Creates a new `ChangePasswordAction` with a custom password policy and hasher.
    pub fn with_hasher(user_repository: U, password_policy: PasswordPolicy, hasher: H) -> Self {
        Self {
            user_repository,
            password_policy,
            hasher,
        }
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "change_password", skip_all, err)
    )]
    pub async fn execute(
        &self,
        user_id: i32,
        current_password: &SecretString,
        new_password: &SecretString,
    ) -> Result<(), AuthError> {
        let user = self.user_repository.find_user_by_id(user_id).await?;

        match user {
            Some(user) => {
                if !self
                    .hasher
                    .verify(current_password.expose_secret(), &user.hashed_password)?
                {
                    return Err(AuthError::InvalidCredentials);
                }

                self.password_policy
                    .validate(new_password.expose_secret())?;

                let hashed = self.hasher.hash(new_password.expose_secret())?;
                self.user_repository.update_password(user_id, &hashed).await
            }
            None => Err(AuthError::UserNotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Argon2Hasher, SecretString};
    use crate::validators::ValidationError;
    use crate::{MockUserRepository, User};

    fn create_user_with_password(email: &str, password: &str) -> User {
        let hashed = Argon2Hasher::default().hash(password).unwrap();
        User::mock_from_credentials(email, &hashed)
    }

    #[tokio::test]
    async fn test_change_password_success() {
        let user_repo = MockUserRepository::new();

        let user = create_user_with_password("user@example.com", "oldpassword");
        let user_id = user.id;
        user_repo.users.lock().unwrap().push(user);

        let action = ChangePasswordAction::new(user_repo);
        let old_password = SecretString::new("oldpassword");
        let new_password = SecretString::new("newpassword");
        let result = action.execute(user_id, &old_password, &new_password).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_change_password_wrong_current() {
        let user_repo = MockUserRepository::new();

        let user = create_user_with_password("user@example.com", "oldpassword");
        let user_id = user.id;
        user_repo.users.lock().unwrap().push(user);

        let action = ChangePasswordAction::new(user_repo);
        let wrong_password = SecretString::new("wrongpassword");
        let new_password = SecretString::new("newpassword");
        let result = action
            .execute(user_id, &wrong_password, &new_password)
            .await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::InvalidCredentials);
    }

    #[tokio::test]
    async fn test_change_password_user_not_found() {
        let user_repo = MockUserRepository::new();

        let action = ChangePasswordAction::new(user_repo);
        let old_password = SecretString::new("old");
        let new_password = SecretString::new("new");
        let result = action.execute(999, &old_password, &new_password).await;

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
        let old_password = SecretString::new("oldpassword");
        let new_password = SecretString::new("short");
        let result = action.execute(user_id, &old_password, &new_password).await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            AuthError::Validation(ValidationError::PasswordTooShort(8))
        );
    }
}
