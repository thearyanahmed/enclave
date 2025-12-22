mod audit_log;
mod email_verification;
mod password_reset;
mod rate_limiter;
mod token;
mod user;

#[cfg(any(test, feature = "mocks"))]
mod audit_log_mock;
#[cfg(any(test, feature = "mocks"))]
mod email_verification_mock;
#[cfg(any(test, feature = "mocks"))]
mod password_reset_mock;
#[cfg(any(test, feature = "mocks"))]
mod rate_limiter_mock;
#[cfg(any(test, feature = "mocks"))]
mod token_mock;
#[cfg(any(test, feature = "mocks"))]
mod user_mock;

pub use audit_log::AuditEventType;
pub use audit_log::AuditLog;
pub use audit_log::AuditLogRepository;
pub use email_verification::EmailVerificationRepository;
pub use email_verification::EmailVerificationToken;
pub use password_reset::PasswordResetRepository;
pub use password_reset::PasswordResetToken;
pub use rate_limiter::LoginAttempt;
pub use rate_limiter::RateLimiterRepository;
pub use token::AccessToken;
pub use token::TokenRepository;
pub use user::User;
pub use user::UserRepository;

#[cfg(test)]
pub use audit_log_mock::MockAuditLogRepository;
#[cfg(test)]
pub use email_verification_mock::MockEmailVerificationRepository;
#[cfg(test)]
pub use password_reset_mock::MockPasswordResetRepository;
#[cfg(test)]
pub use rate_limiter_mock::MockRateLimiterRepository;
#[cfg(test)]
pub use token_mock::MockTokenRepository;
#[cfg(test)]
pub use user_mock::MockUserRepository;
