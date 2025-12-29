use crate::crypto::{Argon2Hasher, PasswordHasher};
use crate::validators::{PasswordPolicy, validate_email};
use crate::{AuthError, AuthUser, SecretString, UserRepository};

pub struct SignupAction<R, H = Argon2Hasher> {
    repository: R,
    password_policy: PasswordPolicy,
    hasher: H,
}

impl<R: UserRepository> SignupAction<R, Argon2Hasher> {
    /// Creates a new `SignupAction` with the default password policy and Argon2 hasher.
    ///
    /// For custom password requirements, use [`with_policy`].
    ///
    /// [`with_policy`]: Self::with_policy
    pub fn new(repository: R) -> Self {
        Self {
            repository,
            password_policy: PasswordPolicy::default(),
            hasher: Argon2Hasher::default(),
        }
    }

    /// Creates a new `SignupAction` with a custom password policy.
    ///
    /// Use [`PasswordPolicy::strict()`] for stronger password requirements.
    ///
    /// [`PasswordPolicy::strict()`]: crate::validators::PasswordPolicy::strict
    pub fn with_policy(repository: R, password_policy: PasswordPolicy) -> Self {
        Self {
            repository,
            password_policy,
            hasher: Argon2Hasher::default(),
        }
    }
}

impl<R: UserRepository, H: PasswordHasher> SignupAction<R, H> {
    /// Creates a new `SignupAction` with a custom password hasher.
    ///
    /// Use this for testing with mock hashers or alternative algorithms.
    pub fn with_hasher(repository: R, password_policy: PasswordPolicy, hasher: H) -> Self {
        Self {
            repository,
            password_policy,
            hasher,
        }
    }

    /// Registers a new user with the given email and password.
    ///
    /// The email must be valid and the password must pass policy validation.
    ///
    /// # Returns
    ///
    /// - `Ok(user)` - user created successfully
    /// - `Err(AuthError::UserAlreadyExists)` - email already registered
    /// - `Err(AuthError::Validation(_))` - invalid email or password
    /// - `Err(_)` - database or other errors
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "signup", skip_all, err)
    )]
    pub async fn execute(
        &self,
        email: &str,
        password: &SecretString,
    ) -> Result<AuthUser, AuthError> {
        validate_email(email)?;
        self.password_policy.validate(password.expose_secret())?;

        if self.repository.find_user_by_email(email).await?.is_some() {
            return Err(AuthError::UserAlreadyExists);
        }

        let hashed = self.hasher.hash(password.expose_secret())?;
        let user = self.repository.create_user(email, &hashed).await?;

        let user_id = user.id;
        log::info!(
            target: "enclave_auth",
            "msg=\"signup success\", user_id={user_id}"
        );

        Ok(user)
    }
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

        let password = SecretString::new("securepassword");
        let result = signup.execute("user@example.com", &password).await;

        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.email, "user@example.com");
    }

    #[tokio::test]
    async fn test_signup_user_already_exists() {
        let existing_user = AuthUser::mock();

        let repo = MockUserRepository::new();
        repo.users.lock().unwrap().push(existing_user);

        let signup = SignupAction::new(repo);
        let password = SecretString::new("newpassword123");
        _ = signup.execute("user@example.com", &password).await;

        let result = signup.execute("user@example.com", &password).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::UserAlreadyExists);
    }

    #[tokio::test]
    async fn test_signup_invalid_email() {
        let repo = MockUserRepository::new();
        let signup = SignupAction::new(repo);

        let password = SecretString::new("securepassword");
        let result = signup.execute("notanemail", &password).await;

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

        let password = SecretString::new("short");
        let result = signup.execute("user@example.com", &password).await;

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
        let weak = SecretString::new("weakpassword");
        let result = signup.execute("user@example.com", &weak).await;
        assert!(result.is_err());

        // Strong password passes
        let strong = SecretString::new("MyStr0ng!Pass");
        let result = signup.execute("user@example.com", &strong).await;
        assert!(result.is_ok());
    }
}
