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
#[cfg(all(feature = "audit_log", any(test, feature = "mocks")))]
pub use audit_log_mock::MockAuditLogRepository;
pub use email_verification::{EmailVerificationRepository, EmailVerificationToken};
#[cfg(any(test, feature = "mocks"))]
pub use email_verification_mock::MockEmailVerificationRepository;
#[cfg(feature = "magic_link")]
pub use magic_link::MagicLinkRepository;
#[cfg(feature = "magic_link")]
pub use magic_link::MagicLinkToken;
#[cfg(all(feature = "magic_link", any(test, feature = "mocks")))]
pub use magic_link_mock::MockMagicLinkRepository;
pub use password_reset::{PasswordResetRepository, PasswordResetToken};
#[cfg(any(test, feature = "mocks"))]
pub use password_reset_mock::MockPasswordResetRepository;
pub use rate_limiter::{LoginAttempt, RateLimiterRepository};
#[cfg(any(test, feature = "mocks"))]
pub use rate_limiter_mock::MockRateLimiterRepository;
pub use token::{AccessToken, CreateTokenOptions, StatefulTokenRepository, TokenRepository};
#[cfg(any(test, feature = "mocks"))]
pub use token_mock::MockTokenRepository;
pub use user::{AuthUser, UserRepository};
#[cfg(any(test, feature = "mocks"))]
pub use user_mock::MockUserRepository;
