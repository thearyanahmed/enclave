use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::AuthError;

/// An access token for API authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    /// The token string (plain-text on creation, hashed in storage).
    pub token: String,
    /// The user who owns this token.
    pub user_id: i32,
    /// Optional name for the token (e.g., "mobile-app", "cli").
    pub name: Option<String>,
    /// Token abilities/scopes. Default is `["*"]` (all abilities).
    pub abilities: Vec<String>,
    /// When the token expires.
    pub expires_at: DateTime<Utc>,
    /// When the token was created.
    pub created_at: DateTime<Utc>,
    /// When the token was last used (updated on each request).
    pub last_used_at: Option<DateTime<Utc>>,
}

impl AccessToken {
    /// Checks if the token has a specific ability.
    pub fn has_ability(&self, ability: &str) -> bool {
        self.abilities.contains(&"*".to_owned()) || self.abilities.contains(&ability.to_owned())
    }

    /// Checks if the token has all of the specified abilities.
    pub fn has_all_abilities(&self, abilities: &[&str]) -> bool {
        abilities.iter().all(|a| self.has_ability(a))
    }

    /// Checks if the token has any of the specified abilities.
    pub fn has_any_ability(&self, abilities: &[&str]) -> bool {
        abilities.iter().any(|a| self.has_ability(a))
    }
}

/// Options for creating a new token.
#[derive(Debug, Clone, Default)]
pub struct CreateTokenOptions {
    /// Optional name for the token.
    pub name: Option<String>,
    /// Token abilities. Defaults to `["*"]` if empty.
    pub abilities: Vec<String>,
}

/// Storage abstraction for access tokens.
///
/// Implementations must hash tokens before storage using [`hash_token`].
/// The plain-text token is returned to the client; only the hash is stored.
///
/// [`hash_token`]: crate::hash_token
#[async_trait]
pub trait TokenRepository: Send + Sync {
    async fn create_token(
        &self,
        user_id: i32,
        expires_at: DateTime<Utc>,
    ) -> Result<AccessToken, AuthError>;

    /// Creates a new token with custom options (name, abilities).
    async fn create_token_with_options(
        &self,
        user_id: i32,
        expires_at: DateTime<Utc>,
        options: CreateTokenOptions,
    ) -> Result<AccessToken, AuthError>;

    /// Finds a token by its plain-text value.
    async fn find_token(&self, token: &str) -> Result<Option<AccessToken>, AuthError>;

    /// Revokes (deletes) a specific token.
    async fn revoke_token(&self, token: &str) -> Result<(), AuthError>;

    /// Revokes all tokens for a user.
    async fn revoke_all_user_tokens(&self, user_id: i32) -> Result<(), AuthError>;

    /// Updates the `last_used_at` timestamp for a token.
    async fn touch_token(&self, token: &str) -> Result<(), AuthError>;

    /// Removes all expired tokens from storage.
    /// Returns the number of tokens removed.
    async fn prune_expired(&self) -> Result<u64, AuthError>;
}
