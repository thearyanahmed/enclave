use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::AuthError;
use crate::SecretString;

/// An access token for API authentication.
///
/// The `token` field uses `SecretString` to prevent accidental logging.
#[derive(Clone, Serialize, Deserialize)]
pub struct AccessToken {
    /// The token string (plain-text on creation, hashed in storage).
    pub token: SecretString,
    /// The user who owns this token.
    pub user_id: i32,
    /// Optional name for the token (e.g., "mobile-app", "cli").
    pub name: Option<String>,
    /// When the token expires.
    pub expires_at: DateTime<Utc>,
    /// When the token was created.
    pub created_at: DateTime<Utc>,
}

impl std::fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessToken")
            .field("token", &"[REDACTED]")
            .field("user_id", &self.user_id)
            .field("name", &self.name)
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Options for creating a new token.
#[derive(Debug, Clone, Default)]
pub struct CreateTokenOptions {
    /// Optional name for the token.
    pub name: Option<String>,
}

/// Storage abstraction for access tokens.
///
/// Implementations must hash tokens before storage using [`hash_token`].
/// The plain-text token is returned to the client; only the hash is stored.
///
/// This trait provides core token operations that work for both stateless (JWT)
/// and stateful (database-backed) tokens.
///
/// [`hash_token`]: crate::hash_token
#[async_trait]
pub trait TokenRepository: Send + Sync {
    /// Creates a new token for a user.
    async fn create_token(
        &self,
        user_id: i32,
        expires_at: DateTime<Utc>,
    ) -> Result<AccessToken, AuthError>;

    /// Creates a new token with custom options.
    async fn create_token_with_options(
        &self,
        user_id: i32,
        expires_at: DateTime<Utc>,
        options: CreateTokenOptions,
    ) -> Result<AccessToken, AuthError>;

    /// Finds a token by its plain-text value.
    async fn find_token(&self, token: &str) -> Result<Option<AccessToken>, AuthError>;
}

/// Extended token operations for stateful (database-backed) tokens.
///
/// This trait provides operations that require persistent storage,
/// such as token revocation and cleanup. JWT tokens are stateless
/// and do not implement this trait.
#[async_trait]
pub trait StatefulTokenRepository: TokenRepository {
    /// Revokes (deletes) a specific token.
    async fn revoke_token(&self, token: &str) -> Result<(), AuthError>;

    /// Revokes all tokens for a user (e.g., "logout from all devices").
    async fn revoke_all_user_tokens(&self, user_id: i32) -> Result<(), AuthError>;

    /// Removes all expired tokens from storage.
    /// Returns the number of tokens removed.
    async fn prune_expired(&self) -> Result<u64, AuthError>;
}
