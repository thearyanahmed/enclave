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
        let code = match &err {
            crate::AuthError::UserNotFound => "USER_NOT_FOUND",
            crate::AuthError::UserAlreadyExists => "USER_ALREADY_EXISTS",
            crate::AuthError::InvalidCredentials => "INVALID_CREDENTIALS",
            crate::AuthError::InvalidEmail => "INVALID_EMAIL",
            crate::AuthError::InvalidPassword => "INVALID_PASSWORD",
            crate::AuthError::PasswordHashError => "PASSWORD_HASH_ERROR",
            crate::AuthError::TokenExpired => "TOKEN_EXPIRED",
            crate::AuthError::TokenInvalid => "TOKEN_INVALID",
            crate::AuthError::EmailAlreadyVerified => "EMAIL_ALREADY_VERIFIED",
            crate::AuthError::TooManyAttempts => "TOO_MANY_ATTEMPTS",
            crate::AuthError::Validation(_) => "VALIDATION_ERROR",
            crate::AuthError::DatabaseError(_) => "DATABASE_ERROR",
            crate::AuthError::ConfigurationError(_) => "CONFIGURATION_ERROR",
            #[allow(deprecated)]
            crate::AuthError::Other(_) => "UNKNOWN_ERROR",
        };

        ErrorResponse {
            error: err.to_string(),
            code: code.to_owned(),
        }
    }
}
