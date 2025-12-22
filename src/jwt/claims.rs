use serde::{Deserialize, Serialize};

use crate::AuthError;

/// Claims embedded in a JWT token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Subject - the user ID.
    pub sub: String,
    /// Expiration time (Unix timestamp).
    pub exp: i64,
    /// Issued at time (Unix timestamp).
    pub iat: i64,
    /// Issuer (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Audience (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
}

impl JwtClaims {
    /// Returns the user ID from the claims.
    pub fn user_id(&self) -> Result<i32, AuthError> {
        self.sub.parse().map_err(|_| AuthError::TokenInvalid)
    }
}
