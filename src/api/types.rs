use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::SecretString;

// Request DTOs

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub name: String,
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

#[cfg(feature = "magic_link")]
#[derive(Debug, Deserialize)]
pub struct MagicLinkRequest {
    pub email: String,
}

#[cfg(feature = "magic_link")]
#[derive(Debug, Deserialize)]
pub struct VerifyMagicLinkRequest {
    pub token: String,
}

// Response DTOs

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: i32,
    pub email: String,
    pub name: String,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub user: UserResponse,
    pub token: SecretString,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for AuthResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthResponse")
            .field("user", &self.user)
            .field("token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub token: SecretString,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl From<crate::AuthUser> for UserResponse {
    fn from(user: crate::AuthUser) -> Self {
        UserResponse {
            id: user.id,
            email: user.email,
            name: user.name,
            email_verified_at: user.email_verified_at,
            created_at: user.created_at,
        }
    }
}

impl From<crate::AuthError> for ErrorResponse {
    #[allow(deprecated)]
    fn from(err: crate::AuthError) -> Self {
        // Sanitize internal errors to prevent information leakage
        let error = match &err {
            crate::AuthError::DatabaseError(_)
            | crate::AuthError::ConfigurationError(_)
            | crate::AuthError::Other(_) => "an internal error occurred".to_owned(),
            _ => err.to_string().to_lowercase(),
        };

        ErrorResponse { error }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_error_is_sanitized() {
        let err =
            crate::AuthError::DatabaseError("ERROR: relation \"users\" does not exist".to_owned());
        let response: ErrorResponse = err.into();

        assert_eq!(response.error, "an internal error occurred");
        assert!(!response.error.contains("users"));
        assert!(!response.error.contains("relation"));
    }

    #[test]
    fn test_configuration_error_is_sanitized() {
        let err = crate::AuthError::ConfigurationError("secret key: abc123xyz".to_owned());
        let response: ErrorResponse = err.into();

        assert_eq!(response.error, "an internal error occurred");
        assert!(!response.error.contains("abc123xyz"));
    }

    #[test]
    #[allow(deprecated)]
    fn test_other_error_is_sanitized() {
        let err = crate::AuthError::Other("internal stack trace here".to_owned());
        let response: ErrorResponse = err.into();

        assert_eq!(response.error, "an internal error occurred");
        assert!(!response.error.contains("stack trace"));
    }

    #[test]
    fn test_user_facing_errors_are_lowercase() {
        let test_cases = [
            (crate::AuthError::UserNotFound, "user not found"),
            (crate::AuthError::UserAlreadyExists, "user already exists"),
            (
                crate::AuthError::InvalidCredentials,
                "invalid email or password",
            ),
            (crate::AuthError::TokenExpired, "token has expired"),
            (crate::AuthError::TokenInvalid, "invalid token"),
        ];

        for (err, expected_message) in test_cases {
            let response: ErrorResponse = err.into();
            assert_eq!(response.error, expected_message);
        }
    }
}
