#[cfg(feature = "audit_log")]
mod audit_log;
mod email_verification;
#[cfg(feature = "magic_link")]
mod magic_link;
pub mod migrations;
mod password_reset;
mod rate_limiter;
#[cfg(feature = "teams")]
mod teams;
mod token;
mod user;

#[cfg(feature = "audit_log")]
pub use audit_log::PostgresAuditLogRepository;
pub use email_verification::PostgresEmailVerificationRepository;
#[cfg(feature = "magic_link")]
pub use magic_link::PostgresMagicLinkRepository;
pub use password_reset::PostgresPasswordResetRepository;
pub use rate_limiter::PostgresRateLimiterRepository;
#[cfg(feature = "teams")]
pub use teams::{
    PostgresTeamInvitationRepository, PostgresTeamMemberPermissionRepository,
    PostgresTeamMembershipRepository, PostgresTeamRepository, PostgresUserTeamContextRepository,
};
pub use token::PostgresTokenRepository;
pub use user::PostgresUserRepository;

use sqlx::PgPool;

/// Creates all Postgres repository instances from a connection pool.
///
/// Returns the core repositories needed for authentication.
/// For audit logging, enable the `audit_log` feature and create
/// `PostgresAuditLogRepository` manually.
pub fn create_repositories(
    pool: PgPool,
) -> (
    PostgresUserRepository,
    PostgresTokenRepository,
    PostgresPasswordResetRepository,
    PostgresEmailVerificationRepository,
    PostgresRateLimiterRepository,
) {
    (
        PostgresUserRepository::new(pool.clone()),
        PostgresTokenRepository::new(pool.clone()),
        PostgresPasswordResetRepository::new(pool.clone()),
        PostgresEmailVerificationRepository::new(pool.clone()),
        PostgresRateLimiterRepository::new(pool),
    )
}
