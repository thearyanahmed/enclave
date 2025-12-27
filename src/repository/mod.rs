//! Repository traits and data types.
//!
//! This module defines the storage abstractions used throughout enclave.
//! Implement these traits to use your own database or storage backend.
//!
//! # Traits
//!
//! | Trait | Description |
//! |-------|-------------|
//! | [`UserRepository`] | User CRUD operations |
//! | [`TokenRepository`] | Token creation and lookup |
//! | [`StatefulTokenRepository`] | Token revocation (extends `TokenRepository`) |
//! | [`PasswordResetRepository`] | Password reset tokens |
//! | [`EmailVerificationRepository`] | Email verification tokens |
//! | [`RateLimiterRepository`] | Login attempt tracking |
//!
//! # Data Types
//!
//! | Type | Description |
//! |------|-------------|
//! | [`AuthUser`] | User account data |
//! | [`AccessToken`] | Authentication token |
//! | [`PasswordResetToken`] | Password reset token |
//! | [`EmailVerificationToken`] | Email verification token |
//!
//! # Mock Implementations
//!
//! Enable the `mocks` feature for in-memory implementations useful for testing:
//!
//! - [`MockUserRepository`]
//! - [`MockTokenRepository`]
//! - [`MockPasswordResetRepository`]
//! - [`MockEmailVerificationRepository`]
//! - [`MockRateLimiterRepository`]

#[cfg(feature = "audit_log")]
mod audit_log;
mod email_verification;
#[cfg(feature = "magic_link")]
mod magic_link;
mod password_reset;
mod rate_limiter;
mod token;
mod user;

#[cfg(all(feature = "audit_log", any(test, feature = "mocks")))]
mod audit_log_mock;
#[cfg(any(test, feature = "mocks"))]
mod email_verification_mock;
#[cfg(all(feature = "magic_link", any(test, feature = "mocks")))]
mod magic_link_mock;
#[cfg(any(test, feature = "mocks"))]
mod password_reset_mock;
#[cfg(any(test, feature = "mocks"))]
mod rate_limiter_mock;
#[cfg(any(test, feature = "mocks"))]
mod token_mock;
#[cfg(any(test, feature = "mocks"))]
mod user_mock;

#[cfg(feature = "audit_log")]
pub use audit_log::AuditEventType;
#[cfg(feature = "audit_log")]
pub use audit_log::AuditLog;
#[cfg(feature = "audit_log")]
pub use audit_log::AuditLogRepository;
pub use email_verification::EmailVerificationRepository;
pub use email_verification::EmailVerificationToken;
#[cfg(feature = "magic_link")]
pub use magic_link::MagicLinkRepository;
#[cfg(feature = "magic_link")]
pub use magic_link::MagicLinkToken;
pub use password_reset::PasswordResetRepository;
pub use password_reset::PasswordResetToken;
pub use rate_limiter::LoginAttempt;
pub use rate_limiter::RateLimiterRepository;
pub use token::AccessToken;
pub use token::CreateTokenOptions;
pub use token::StatefulTokenRepository;
pub use token::TokenRepository;
pub use user::AuthUser;
pub use user::UserRepository;

#[cfg(all(feature = "audit_log", any(test, feature = "mocks")))]
pub use audit_log_mock::MockAuditLogRepository;
#[cfg(any(test, feature = "mocks"))]
pub use email_verification_mock::MockEmailVerificationRepository;
#[cfg(all(feature = "magic_link", any(test, feature = "mocks")))]
pub use magic_link_mock::MockMagicLinkRepository;
#[cfg(any(test, feature = "mocks"))]
pub use password_reset_mock::MockPasswordResetRepository;
#[cfg(any(test, feature = "mocks"))]
pub use rate_limiter_mock::MockRateLimiterRepository;
#[cfg(any(test, feature = "mocks"))]
pub use token_mock::MockTokenRepository;
#[cfg(any(test, feature = "mocks"))]
pub use user_mock::MockUserRepository;
