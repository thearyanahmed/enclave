use serde::{Deserialize, Serialize};

use crate::AuthError;

/// Type of JWT token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    /// Short-lived access token for API requests.
    Access,
    /// Long-lived refresh token for obtaining new access tokens.
    Refresh,
}

/// Claims embedded in a JWT token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Subject - the user ID.
    pub sub: String,
    /// Expiration time (Unix timestamp).
    pub exp: i64,
    /// Issued at time (Unix timestamp).
    pub iat: i64,
    /// Token type (access or refresh).
    #[serde(rename = "typ", default = "default_token_type")]
    pub token_type: TokenType,
    /// Issuer (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Audience (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
}

fn default_token_type() -> TokenType {
    TokenType::Access
}

impl JwtClaims {
    /// Returns the user ID from the claims.
    pub fn user_id(&self) -> Result<i32, AuthError> {
        self.sub.parse().map_err(|_| AuthError::TokenInvalid)
    }

    /// Returns true if this is an access token.
    pub fn is_access_token(&self) -> bool {
        self.token_type == TokenType::Access
    }

    /// Returns true if this is a refresh token.
    pub fn is_refresh_token(&self) -> bool {
        self.token_type == TokenType::Refresh
    }
}
