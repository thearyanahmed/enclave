use crate::SecretString;
use crate::crypto::{Argon2Hasher, PasswordHasher};
use crate::validators::PasswordPolicy;
use crate::{AuthError, StatefulTokenRepository, UserRepository};

/// Configuration for password change behavior.
///
/// # Example
///
/// ```rust
/// use enclave::actions::ChangePasswordConfig;
///
/// // Default: revoke all sessions after password change
/// let config = ChangePasswordConfig::default();
/// assert!(config.revoke_all_sessions);
///
/// // Disable session revocation
/// let config = ChangePasswordConfig {
///     revoke_all_sessions: false,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct ChangePasswordConfig {
    /// Whether to revoke all user sessions (tokens) after a password change.
    ///
    /// When enabled and a token repository is provided, all existing access tokens
    /// for the user will be invalidated, forcing re-authentication on all devices.
    ///
    /// **Security recommendation:** Keep this enabled (default) to prevent
    /// compromised sessions from remaining active after a password change.
    ///
    /// Default: `true`
    pub revoke_all_sessions: bool,
}

impl Default for ChangePasswordConfig {
    fn default() -> Self {
        Self {
            revoke_all_sessions: true,
        }
    }
}

/// Marker type indicating no token revocation capability.
///
/// Used as the default type parameter when `ChangePasswordAction` is created
/// without a token repository.
#[derive(Debug, Clone, Copy)]
pub struct NoTokenRevocation;

pub struct ChangePasswordAction<U, T = NoTokenRevocation, H = Argon2Hasher>
where
    U: UserRepository,
{
    user_repository: U,
    token_repository: T,
    password_policy: PasswordPolicy,
    config: ChangePasswordConfig,
    hasher: H,
}

// Constructors without token repository (backwards compatible)
impl<U: UserRepository> ChangePasswordAction<U, NoTokenRevocation, Argon2Hasher> {
    /// Creates a new `ChangePasswordAction` with the default password policy and hasher.
    ///
    /// Token revocation is disabled. To enable it, use [`with_token_repository`].
    ///
    /// [`with_token_repository`]: Self::with_token_repository
    pub fn new(user_repository: U) -> Self {
        Self {
            user_repository,
            token_repository: NoTokenRevocation,
            password_policy: PasswordPolicy::default(),
            config: ChangePasswordConfig::default(),
            hasher: Argon2Hasher::default(),
        }
    }

    /// Creates a new `ChangePasswordAction` with a custom password policy.
    ///
    /// Token revocation is disabled. To enable it, use [`with_token_repository`].
    ///
    /// [`with_token_repository`]: Self::with_token_repository
    pub fn with_policy(user_repository: U, password_policy: PasswordPolicy) -> Self {
        Self {
            user_repository,
            token_repository: NoTokenRevocation,
            password_policy,
            config: ChangePasswordConfig::default(),
            hasher: Argon2Hasher::default(),
        }
    }
}

// Builder methods to add token repository
impl<U: UserRepository, H: PasswordHasher> ChangePasswordAction<U, NoTokenRevocation, H> {
    /// Adds a token repository to enable session revocation on password change.
    ///
    /// When `config.revoke_all_sessions` is `true` (default), all user tokens
    /// will be revoked after a successful password change.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let action = ChangePasswordAction::new(user_repo)
    ///     .with_token_repository(token_repo);
    ///
    /// // After password change, all user sessions are revoked
    /// action.execute(user_id, &old_password, &new_password).await?;
    /// ```
    pub fn with_token_repository<T: StatefulTokenRepository>(
        self,
        token_repository: T,
    ) -> ChangePasswordAction<U, T, H> {
        ChangePasswordAction {
            user_repository: self.user_repository,
            token_repository,
            password_policy: self.password_policy,
            config: self.config,
            hasher: self.hasher,
        }
    }
}

// Configuration methods (available for all variants)
impl<U: UserRepository, T, H: PasswordHasher> ChangePasswordAction<U, T, H> {
    /// Sets the configuration for password change behavior.
    #[must_use]
    pub fn with_config(mut self, config: ChangePasswordConfig) -> Self {
        self.config = config;
        self
    }

    /// Sets whether to revoke all sessions after password change.
    ///
    /// This is a convenience method equivalent to:
    /// ```rust,ignore
    /// action.with_config(ChangePasswordConfig { revoke_all_sessions: value })
    /// ```
    #[must_use]
    pub fn revoke_sessions(mut self, revoke: bool) -> Self {
        self.config.revoke_all_sessions = revoke;
        self
    }
}

impl<U: UserRepository, H: PasswordHasher> ChangePasswordAction<U, NoTokenRevocation, H> {
    /// Creates a new `ChangePasswordAction` with a custom password policy and hasher.
    pub fn with_hasher(user_repository: U, password_policy: PasswordPolicy, hasher: H) -> Self {
        Self {
            user_repository,
            token_repository: NoTokenRevocation,
            password_policy,
            config: ChangePasswordConfig::default(),
            hasher,
        }
    }
}

// Execute without token revocation
impl<U: UserRepository, H: PasswordHasher> ChangePasswordAction<U, NoTokenRevocation, H> {
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
        self.execute_password_change(user_id, current_password, new_password)
            .await
    }
}

// Execute with token revocation
impl<U: UserRepository, T: StatefulTokenRepository, H: PasswordHasher>
    ChangePasswordAction<U, T, H>
{
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
        self.execute_password_change(user_id, current_password, new_password)
            .await?;

        // Revoke all sessions if configured
        if self.config.revoke_all_sessions {
            self.token_repository
                .revoke_all_user_tokens(user_id)
                .await?;
        }

        Ok(())
    }
}

// Shared password change logic
impl<U: UserRepository, T, H: PasswordHasher> ChangePasswordAction<U, T, H> {
    async fn execute_password_change(
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
    use crate::SecretString;
    use crate::crypto::Argon2Hasher;
    use crate::validators::ValidationError;
    use crate::{MockTokenRepository, MockUserRepository, TokenRepository, User};

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

    #[tokio::test]
    async fn test_change_password_revokes_sessions() {
        let user_repo = MockUserRepository::new();
        let token_repo = MockTokenRepository::new();

        let user = create_user_with_password("user@example.com", "oldpassword");
        let user_id = user.id;
        user_repo.users.lock().unwrap().push(user);

        // Create some tokens for the user
        let expires = chrono::Utc::now() + chrono::Duration::days(1);
        token_repo.create_token(user_id, expires).await.unwrap();
        token_repo.create_token(user_id, expires).await.unwrap();
        assert_eq!(token_repo.tokens.lock().unwrap().len(), 2);

        let action = ChangePasswordAction::new(user_repo).with_token_repository(token_repo.clone());

        let old_password = SecretString::new("oldpassword");
        let new_password = SecretString::new("newpassword");
        let result = action.execute(user_id, &old_password, &new_password).await;

        assert!(result.is_ok());
        // All tokens should be revoked
        assert_eq!(token_repo.tokens.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_change_password_no_revoke_when_disabled() {
        let user_repo = MockUserRepository::new();
        let token_repo = MockTokenRepository::new();

        let user = create_user_with_password("user@example.com", "oldpassword");
        let user_id = user.id;
        user_repo.users.lock().unwrap().push(user);

        // Create some tokens for the user
        let expires = chrono::Utc::now() + chrono::Duration::days(1);
        token_repo.create_token(user_id, expires).await.unwrap();
        token_repo.create_token(user_id, expires).await.unwrap();
        assert_eq!(token_repo.tokens.lock().unwrap().len(), 2);

        let action = ChangePasswordAction::new(user_repo)
            .with_token_repository(token_repo.clone())
            .revoke_sessions(false);

        let old_password = SecretString::new("oldpassword");
        let new_password = SecretString::new("newpassword");
        let result = action.execute(user_id, &old_password, &new_password).await;

        assert!(result.is_ok());
        // Tokens should NOT be revoked
        assert_eq!(token_repo.tokens.lock().unwrap().len(), 2);
    }
}
