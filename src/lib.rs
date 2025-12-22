// allow unwrap/expect in test code
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod actions;
#[cfg(feature = "actix")]
pub mod api;
pub mod crypto;
#[cfg(feature = "sqlx_postgres")]
pub mod postgres;
pub mod repository;
pub mod validators;

pub use crypto::hash_token;

pub use repository::UserRepository;
pub use repository::TokenRepository;
pub use repository::PasswordResetRepository;
pub use repository::EmailVerificationRepository;
pub use repository::RateLimiterRepository;
pub use repository::AuditLogRepository;
pub use repository::User;
pub use repository::AccessToken;
pub use repository::PasswordResetToken;
pub use repository::EmailVerificationToken;
pub use repository::LoginAttempt;
pub use repository::AuditLog;
pub use repository::AuditEventType;

pub use repository::MockUserRepository;
pub use repository::MockTokenRepository;
pub use repository::MockPasswordResetRepository;
pub use repository::MockEmailVerificationRepository;
pub use repository::MockRateLimiterRepository;
pub use repository::MockAuditLogRepository;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
        Self::Validation(err)
    }
}

impl fmt::Display for AuthError {
    #[allow(deprecated)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserNotFound => write!(f, "User not found"),
            Self::UserAlreadyExists => write!(f, "User already exists"),
            Self::InvalidCredentials => write!(f, "Invalid email or password"),
            Self::InvalidEmail => write!(f, "Invalid email format"),
            Self::InvalidPassword => write!(f, "Invalid password"),
            Self::PasswordHashError => write!(f, "Failed to hash password"),
            Self::TokenExpired => write!(f, "Token has expired"),
            Self::TokenInvalid => write!(f, "Invalid token"),
            Self::EmailAlreadyVerified => write!(f, "Email is already verified"),
            Self::TooManyAttempts => write!(f, "Too many failed attempts, please try again later"),
            Self::Validation(err) => write!(f, "Validation error: {err}"),
            Self::DatabaseError(msg) => write!(f, "Database error: {msg}"),
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

