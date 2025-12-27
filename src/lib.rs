//! # Enclave
//!
//! Authentication library for Rust applications.
//!
//! Enclave provides the building blocks for user authentication: password hashing,
//! token management, rate limiting, and optional HTTP/database integrations.
//! It uses a trait-based architecture allowing custom storage backends.
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use enclave::actions::SignupAction;
//! use enclave::{MockUserRepository, Argon2Hasher, SecretString};
//!
//! let user_repo = MockUserRepository::new();
//! let hasher = Argon2Hasher::default();
//!
//! let signup = SignupAction::new(user_repo, hasher);
//! let password = SecretString::new("secure_password123");
//! let user = signup.execute("user@example.com", &password).await?;
//! ```
//!
//! # Feature Flags
//!
//! Enclave uses feature flags to minimize dependencies. Enable only what you need.
//!
//! | Feature | Description |
//! |---------|-------------|
//! | `actix` | HTTP handlers and routes for [actix-web](https://actix.rs/) |
//! | `sqlx_postgres` | `PostgreSQL` repository implementations via [sqlx](https://docs.rs/sqlx) |
//! | `jwt` | JWT token provider using [jsonwebtoken](https://docs.rs/jsonwebtoken) |
//! | `mocks` | In-memory mock repositories for testing |
//! | `tracing` | Span instrumentation for all actions |
//! | `rate_limit` | Rate limiting middleware and utilities |
//! | `sessions` | Cookie-based session authentication |
//! | `magic_link` | Passwordless magic link authentication |
//! | `audit_log` | Security event audit logging |
//!
//! # Architecture
//!
//! ## Actions
//!
//! Business logic is encapsulated in action structs. Each action accepts repository
//! traits and executes a specific operation.
//!
//! - [`actions::SignupAction`] - Register new user
//! - [`actions::LoginAction`] - Authenticate user, return token
//! - [`actions::LogoutAction`] - Revoke token (stateful only)
//! - [`actions::ForgotPasswordAction`] - Create password reset token
//! - [`actions::ResetPasswordAction`] - Reset password with token
//! - [`actions::RefreshTokenAction`] - Issue new token (stateful only)
//! - [`actions::SendVerificationAction`] - Create email verification token
//! - [`actions::VerifyEmailAction`] - Mark email as verified
//! - [`actions::ChangePasswordAction`] - Change password (authenticated)
//! - [`actions::UpdateUserAction`] - Update user profile
//! - [`actions::DeleteUserAction`] - Delete user account
//! - [`actions::GetUserAction`] - Retrieve user by ID
//!
//! ## Repository Traits
//!
//! Storage is abstracted through traits. Implement these for custom backends.
//!
//! - [`UserRepository`] - User CRUD operations
//! - [`TokenRepository`] - Token creation and lookup
//! - [`StatefulTokenRepository`] - Token revocation (extends `TokenRepository`)
//! - [`PasswordResetRepository`] - Password reset tokens
//! - [`EmailVerificationRepository`] - Email verification tokens
//! - [`RateLimiterRepository`] - Login attempt tracking
//!
//! ## Modules
//!
//! - [`actions`] - Business logic actions
//! - [`config`] - Configuration structs ([`AuthConfig`], [`TokenConfig`])
//! - [`crypto`] - Password hashing ([`Argon2Hasher`]) and token utilities
//! - [`repository`] - Repository traits and data types
//! - [`validators`] - Input validation ([`PasswordPolicy`])
//! - [`secret`] - Sensitive data wrapper ([`SecretString`])
//!
//! ### Feature-gated Modules
//!
//! - [`api`] - HTTP layer for actix-web *(requires `actix`)*
//! - [`postgres`] - `PostgreSQL` implementations *(requires `sqlx_postgres`)*
//! - [`jwt`] - JWT token provider *(requires `jwt`)*
//! - [`rate_limit`] - Rate limiting *(requires `rate_limit`)*
//! - [`session`] - Cookie sessions *(requires `sessions`)*
//!
//! # Security
//!
//! - **Password hashing**: Argon2id (OWASP 2024 recommended)
//! - **Token storage**: SHA-256 hashed before database storage
//! - **Rate limiting**: Configurable per-endpoint limits
//! - **Secret protection**: [`SecretString`] prevents accidental logging
//!
//! See [SECURITY.md](https://github.com/thearyanahmed/enclave/blob/master/SECURITY.md)
//! for the full threat model.

// allow unwrap/expect in test code
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod actions;
#[cfg(any(feature = "actix", feature = "axum_api"))]
pub mod api;
pub mod config;
pub mod crypto;
#[cfg(feature = "jwt")]
pub mod jwt;
#[cfg(feature = "sqlx_postgres")]
pub mod postgres;
#[cfg(feature = "rate_limit")]
pub mod rate_limit;
pub mod repository;
pub mod secret;
#[cfg(feature = "sessions")]
pub mod session;
pub mod validators;

pub use config::AuthConfig;
pub use config::RateLimitConfig;
pub use config::TokenConfig;
pub use crypto::Argon2Hasher;
pub use crypto::DEFAULT_TOKEN_LENGTH;
pub use crypto::PasswordHasher;
pub use crypto::generate_token;
pub use crypto::generate_token_default;
pub use crypto::hash_token;
pub use secret::SecretString;
pub use validators::PasswordPolicy;

pub use repository::AccessToken;
#[cfg(feature = "audit_log")]
pub use repository::AuditEventType;
#[cfg(feature = "audit_log")]
pub use repository::AuditLog;
#[cfg(feature = "audit_log")]
pub use repository::AuditLogRepository;
pub use repository::AuthUser;
pub use repository::EmailVerificationRepository;
pub use repository::EmailVerificationToken;
pub use repository::LoginAttempt;
#[cfg(feature = "magic_link")]
pub use repository::MagicLinkRepository;
#[cfg(feature = "magic_link")]
pub use repository::MagicLinkToken;
pub use repository::PasswordResetRepository;
pub use repository::PasswordResetToken;
pub use repository::RateLimiterRepository;
pub use repository::StatefulTokenRepository;
pub use repository::TokenRepository;
pub use repository::UserRepository;

#[cfg(all(feature = "audit_log", any(test, feature = "mocks")))]
pub use repository::MockAuditLogRepository;
#[cfg(any(test, feature = "mocks"))]
pub use repository::MockEmailVerificationRepository;
#[cfg(all(feature = "magic_link", any(test, feature = "mocks")))]
pub use repository::MockMagicLinkRepository;
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
    ConfigurationError(String),
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
            AuthError::ConfigurationError(msg) => write!(f, "Configuration error: {msg}"),
            AuthError::DatabaseError(msg) => write!(f, "Database error: {msg}"),
            AuthError::Other(msg) => write!(f, "{msg}"),
        }
    }
}
