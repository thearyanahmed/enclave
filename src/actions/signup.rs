use crate::validators::{PasswordPolicy, validate_email};
use crate::{AuthError, User, UserRepository};
use argon2::{Argon2, PasswordHasher};
use password_hash::SaltString;
use rand::rngs::OsRng;

pub struct SignupAction<R> {
    repository: R,
    password_policy: PasswordPolicy,
}

impl<R: UserRepository> SignupAction<R> {
    /// Creates a new `SignupAction` with the default password policy.
    pub fn new(repository: R) -> Self {
        Self {
            repository,
            password_policy: PasswordPolicy::default(),
        }
    }

    /// Creates a new `SignupAction` with a custom password policy.
    pub fn with_policy(repository: R, password_policy: PasswordPolicy) -> Self {
        Self {
            repository,
            password_policy,
        }
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "signup", skip_all, err)
    )]
    pub async fn execute(&self, email: &str, password: &str) -> Result<User, AuthError> {
        validate_email(email)?;
        self.password_policy.validate(password)?;

        if self.repository.find_user_by_email(email).await?.is_some() {
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
    use crate::validators::{PasswordPolicy, ValidationError};

    #[tokio::test]
    async fn test_signup_success() {
        let repo = MockUserRepository::new();
        let signup = SignupAction::new(repo);

        let result = signup.execute("user@example.com", "securepassword").await;

        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.email, "user@example.com");
    }

    #[tokio::test]
    async fn test_signup_user_already_exists() {
        let existing_user = User::mock();

        let repo = MockUserRepository::new();
        repo.users.lock().unwrap().push(existing_user);

        let signup = SignupAction::new(repo);
        _ = signup.execute("user@example.com", "newpassword123").await;

        let result = signup.execute("user@example.com", "newpassword123").await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::UserAlreadyExists);
    }

    #[tokio::test]
    async fn test_signup_invalid_email() {
        let repo = MockUserRepository::new();
        let signup = SignupAction::new(repo);

        let result = signup.execute("notanemail", "securepassword").await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            AuthError::Validation(ValidationError::EmailInvalidFormat)
        );
    }

    #[tokio::test]
    async fn test_signup_password_too_short() {
        let repo = MockUserRepository::new();
        let signup = SignupAction::new(repo);

        let result = signup.execute("user@example.com", "short").await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            AuthError::Validation(ValidationError::PasswordTooShort(8))
        );
    }

    #[tokio::test]
    async fn test_signup_with_strict_policy() {
        let repo = MockUserRepository::new();
        let policy = PasswordPolicy::strict();
        let signup = SignupAction::with_policy(repo, policy);

        // Weak password fails strict policy
        let result = signup.execute("user@example.com", "weakpassword").await;
        assert!(result.is_err());

        // Strong password passes
        let result = signup.execute("user@example.com", "MyStr0ng!Pass").await;
        assert!(result.is_ok());
    }
}
