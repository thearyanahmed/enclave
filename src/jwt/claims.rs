use serde::{Deserialize, Serialize};

use crate::AuthError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    Access,
    Refresh,
}

/// JWT standard claims. Field names follow RFC 7519.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// subject (user ID)
    pub sub: String,
    /// expiration time (unix timestamp)
    pub exp: i64,
    /// issued at (unix timestamp)
    pub iat: i64,
    /// JWT ID
    pub jti: String,
    #[serde(rename = "typ", default = "default_token_type")]
    pub token_type: TokenType,
    /// issuer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// audience
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
}

fn default_token_type() -> TokenType {
    TokenType::Access
}

impl JwtClaims {
    pub fn user_id(&self) -> Result<i64, AuthError> {
        self.sub.parse().map_err(|_| AuthError::TokenInvalid)
    }

    pub fn jti(&self) -> &str {
        &self.jti
    }

    pub fn is_access_token(&self) -> bool {
        self.token_type == TokenType::Access
    }

    pub fn is_refresh_token(&self) -> bool {
        self.token_type == TokenType::Refresh
    }
}
