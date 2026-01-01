use chrono::Utc;

use crate::crypto::{Argon2Hasher, PasswordHasher};
use crate::events::{AuthEvent, dispatch};
use crate::validators::PasswordPolicy;
use crate::{AuthError, SecretString, StatefulTokenRepository, UserRepository};

#[derive(Debug, Clone)]
pub struct ChangePasswordConfig {
    /// Whether to revoke all user sessions (tokens) after a password change.
    ///
    /// When enabled and a token repository is provided, all existing access tokens
    /// for the user will be invalidated, forcing re-authentication on all devices.
    /// Keep enabled (default: true) to prevent compromised sessions from remaining active.
    pub revoke_all_sessions: bool,
}

impl Default for ChangePasswordConfig {
    fn default() -> Self {
        Self {
            revoke_all_sessions: true,
        }
    }
}

/// marker type for when no token repository is provided
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
    /// [`with_token_repository`]: ChangePasswordAction::with_token_repository
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

impl<U: UserRepository, H: PasswordHasher> ChangePasswordAction<U, NoTokenRevocation, H> {
    /// Enables token revocation by providing a `StatefulTokenRepository`.
    ///
    /// When enabled, all user sessions will be invalidated after a password change
    /// (controlled by [`revoke_sessions`]). This is the recommended security practice.
    ///
    /// [`revoke_sessions`]: ChangePasswordAction::revoke_sessions
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

impl<U: UserRepository, T, H: PasswordHasher> ChangePasswordAction<U, T, H> {
    #[must_use]
    pub fn with_config(mut self, config: ChangePasswordConfig) -> Self {
        self.config = config;
        self
    }

    #[must_use]
    pub fn revoke_sessions(mut self, revoke: bool) -> Self {
        self.config.revoke_all_sessions = revoke;
        self
    }
}

impl<U: UserRepository, H: PasswordHasher> ChangePasswordAction<U, NoTokenRevocation, H> {
    /// Creates a new `ChangePasswordAction` with a custom password hasher.
    ///
    /// Use this for testing with mock hashers or alternative algorithms.
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

impl<U: UserRepository, H: PasswordHasher> ChangePasswordAction<U, NoTokenRevocation, H> {
    /// Changes the user's password after verifying the current password.
    ///
    /// The new password must pass the configured password policy validation.
    ///
    /// # Returns
    ///
    /// - `Ok(())` - password changed successfully
    /// - `Err(AuthError::UserNotFound)` - user does not exist
    /// - `Err(AuthError::InvalidCredentials)` - current password is incorrect
    /// - `Err(AuthError::Validation(_))` - new password fails policy validation
    /// - `Err(_)` - database or other errors
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "change_password", skip_all, err)
    )]
    pub async fn execute(
        &self,
        user_id: i64,
        current_password: &SecretString,
        new_password: &SecretString,
    ) -> Result<(), AuthError> {
        self.execute_password_change(user_id, current_password, new_password)
            .await
    }
}

impl<U: UserRepository, T: StatefulTokenRepository, H: PasswordHasher>
    ChangePasswordAction<U, T, H>
{
    /// Changes the user's password after verifying the current password.
    ///
    /// The new password must pass the configured password policy validation.
    /// When `revoke_all_sessions` is enabled (default), all existing tokens
    /// are invalidated after the password change.
    ///
    /// # Returns
    ///
    /// - `Ok(())` - password changed successfully (sessions revoked if configured)
    /// - `Err(AuthError::UserNotFound)` - user does not exist
    /// - `Err(AuthError::InvalidCredentials)` - current password is incorrect
    /// - `Err(AuthError::Validation(_))` - new password fails policy validation
    /// - `Err(_)` - database or other errors
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "change_password", skip_all, err)
    )]
    pub async fn execute(
        &self,
        user_id: i64,
        current_password: &SecretString,
        new_password: &SecretString,
    ) -> Result<(), AuthError> {
        self.execute_password_change(user_id, current_password, new_password)
            .await?;

        if self.config.revoke_all_sessions {
            self.token_repository
                .revoke_all_user_tokens(user_id)
                .await?;

            dispatch(AuthEvent::AllTokensRevoked {
                user_id,
                at: Utc::now(),
            })
            .await;
        }

        Ok(())
    }
}

impl<U: UserRepository, T, H: PasswordHasher> ChangePasswordAction<U, T, H> {
    async fn execute_password_change(
        &self,
        user_id: i64,
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
                self.user_repository
                    .update_password(user_id, &hashed)
                    .await?;

                dispatch(AuthEvent::PasswordChanged {
                    user_id,
                    at: Utc::now(),
                })
                .await;

                log::info!(
                    target: "enclave_auth",
                    "msg=\"password changed\", user_id={user_id}"
                );

                Ok(())
            }
            None => Err(AuthError::UserNotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Argon2Hasher;
    use crate::validators::ValidationError;
    use crate::{AuthUser, MockTokenRepository, MockUserRepository, SecretString, TokenRepository};

    fn create_user_with_password(email: &str, password: &str) -> AuthUser {
        let hashed = Argon2Hasher::default().hash(password).unwrap();
        AuthUser::mock_from_credentials(email, &hashed)
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
