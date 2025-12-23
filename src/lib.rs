// allow unwrap/expect in test code
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod actions;
#[cfg(feature = "actix")]
pub mod api;
pub mod config;
pub mod crypto;
#[cfg(feature = "jwt")]
pub mod jwt;
#[cfg(feature = "sqlx_postgres")]
pub mod postgres;
pub mod repository;
pub mod validators;

pub use config::AuthConfig;
pub use config::RateLimitConfig;
pub use config::TokenConfig;
pub use crypto::DEFAULT_TOKEN_LENGTH;
pub use crypto::generate_token;
pub use crypto::generate_token_default;
pub use crypto::hash_token;

pub use repository::AccessToken;
#[cfg(feature = "_audit_log")]
pub use repository::AuditEventType;
#[cfg(feature = "_audit_log")]
pub use repository::AuditLog;
#[cfg(feature = "_audit_log")]
pub use repository::AuditLogRepository;
pub use repository::EmailVerificationRepository;
pub use repository::EmailVerificationToken;
pub use repository::LoginAttempt;
pub use repository::PasswordResetRepository;
pub use repository::PasswordResetToken;
pub use repository::RateLimiterRepository;
pub use repository::TokenRepository;
pub use repository::User;
pub use repository::UserRepository;

#[cfg(all(feature = "_audit_log", any(test, feature = "mocks")))]
pub use repository::MockAuditLogRepository;
#[cfg(any(test, feature = "mocks"))]
pub use repository::MockEmailVerificationRepository;
#[cfg(any(test, feature = "mocks"))]
pub use repository::MockPasswordResetRepository;
#[cfg(any(test, feature = "mocks"))]
pub use repository::MockRateLimiterRepository;
#[cfg(any(test, feature = "mocks"))]
pub use repository::MockTokenRepository;
#[cfg(any(test, feature = "mocks"))]
pub use repository::MockUserRepository;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthError {
    UserNotFound,
    UserAlreadyExists,
    InvalidCredentials,
    InvalidEmail,
    InvalidPassword,
    PasswordHashError,
    TokenExpired,
    TokenInvalid,
    EmailAlreadyVerified,
    TooManyAttempts,
    Validation(validators::ValidationError),
    DatabaseError(String),
    #[deprecated(note = "Use specific error variants instead")]
    Other(String),
}

impl std::error::Error for AuthError {}

impl From<validators::ValidationError> for AuthError {
    fn from(err: validators::ValidationError) -> Self {
        AuthError::Validation(err)
    }
}

impl fmt::Display for AuthError {
    #[allow(deprecated)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::UserNotFound => write!(f, "User not found"),
            AuthError::UserAlreadyExists => write!(f, "User already exists"),
            AuthError::InvalidCredentials => write!(f, "Invalid email or password"),
            AuthError::InvalidEmail => write!(f, "Invalid email format"),
            AuthError::InvalidPassword => write!(f, "Invalid password"),
            AuthError::PasswordHashError => write!(f, "Failed to hash password"),
            AuthError::TokenExpired => write!(f, "Token has expired"),
            AuthError::TokenInvalid => write!(f, "Invalid token"),
            AuthError::EmailAlreadyVerified => write!(f, "Email is already verified"),
            AuthError::TooManyAttempts => {
                write!(f, "Too many failed attempts, please try again later")
            }
            AuthError::Validation(err) => write!(f, "Validation error: {err}"),
            AuthError::DatabaseError(msg) => write!(f, "Database error: {msg}"),
            AuthError::Other(msg) => write!(f, "{msg}"),
        }
    }
}
