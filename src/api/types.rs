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
    pub code: String,
}

impl From<crate::User> for UserResponse {
    fn from(user: crate::User) -> Self {
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
    fn from(err: crate::AuthError) -> Self {
        // Map error to code and determine if message should be sanitized
        let (code, sanitized_message) = match &err {
            crate::AuthError::UserNotFound => ("USER_NOT_FOUND", None),
            crate::AuthError::UserAlreadyExists => ("USER_ALREADY_EXISTS", None),
            crate::AuthError::InvalidCredentials => ("INVALID_CREDENTIALS", None),
            crate::AuthError::InvalidEmail => ("INVALID_EMAIL", None),
            crate::AuthError::InvalidPassword => ("INVALID_PASSWORD", None),
            crate::AuthError::PasswordHashError => ("PASSWORD_HASH_ERROR", None),
            crate::AuthError::TokenExpired => ("TOKEN_EXPIRED", None),
            crate::AuthError::TokenInvalid => ("TOKEN_INVALID", None),
            crate::AuthError::EmailAlreadyVerified => ("EMAIL_ALREADY_VERIFIED", None),
            crate::AuthError::TooManyAttempts => ("TOO_MANY_ATTEMPTS", None),
            crate::AuthError::Validation(_) => ("VALIDATION_ERROR", None),
            // Sanitize internal errors to prevent information leakage
            crate::AuthError::DatabaseError(_) => {
                ("DATABASE_ERROR", Some("An internal error occurred"))
            }
            crate::AuthError::ConfigurationError(_) => {
                ("CONFIGURATION_ERROR", Some("An internal error occurred"))
            }
            #[allow(deprecated)]
            crate::AuthError::Other(_) => ("UNKNOWN_ERROR", Some("An internal error occurred")),
        };

        ErrorResponse {
            error: sanitized_message.map_or_else(|| err.to_string(), ToOwned::to_owned),
            code: code.to_owned(),
        }
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

        assert_eq!(response.code, "DATABASE_ERROR");
        assert_eq!(response.error, "An internal error occurred");
        assert!(!response.error.contains("users"));
        assert!(!response.error.contains("relation"));
    }

    #[test]
    fn test_configuration_error_is_sanitized() {
        let err = crate::AuthError::ConfigurationError("secret key: abc123xyz".to_owned());
        let response: ErrorResponse = err.into();

        assert_eq!(response.code, "CONFIGURATION_ERROR");
        assert_eq!(response.error, "An internal error occurred");
        assert!(!response.error.contains("abc123xyz"));
    }

    #[test]
    #[allow(deprecated)]
    fn test_other_error_is_sanitized() {
        let err = crate::AuthError::Other("internal stack trace here".to_owned());
        let response: ErrorResponse = err.into();

        assert_eq!(response.code, "UNKNOWN_ERROR");
        assert_eq!(response.error, "An internal error occurred");
        assert!(!response.error.contains("stack trace"));
    }

    #[test]
    fn test_user_facing_errors_preserve_message() {
        let test_cases = [
            (
                crate::AuthError::UserNotFound,
                "USER_NOT_FOUND",
                "User not found",
            ),
            (
                crate::AuthError::UserAlreadyExists,
                "USER_ALREADY_EXISTS",
                "User already exists",
            ),
            (
                crate::AuthError::InvalidCredentials,
                "INVALID_CREDENTIALS",
                "Invalid email or password",
            ),
            (
                crate::AuthError::TokenExpired,
                "TOKEN_EXPIRED",
                "Token has expired",
            ),
            (
                crate::AuthError::TokenInvalid,
                "TOKEN_INVALID",
                "Invalid token",
            ),
        ];

        for (err, expected_code, expected_message) in test_cases {
            let response: ErrorResponse = err.into();
            assert_eq!(response.code, expected_code);
            assert_eq!(response.error, expected_message);
        }
    }
}
