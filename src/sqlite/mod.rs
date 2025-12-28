//! `SQLite` database backend implementations.
//!
//! This module provides `SQLite`-backed implementations for all repository traits.
//! Enable the `sqlx_sqlite` feature to use these implementations.

#[cfg(feature = "audit_log")]
mod audit_log;
mod email_verification;
#[cfg(feature = "magic_link")]
mod magic_link;
pub mod migrations;
mod password_reset;
#[cfg(feature = "rate_limit")]
mod rate_limit_store;
mod rate_limiter;
#[cfg(feature = "teams")]
mod teams;
mod token;
mod user;

#[cfg(feature = "audit_log")]
pub use audit_log::SqliteAuditLogRepository;
pub use email_verification::SqliteEmailVerificationRepository;
#[cfg(feature = "magic_link")]
pub use magic_link::SqliteMagicLinkRepository;
pub use password_reset::SqlitePasswordResetRepository;
#[cfg(feature = "rate_limit")]
pub use rate_limit_store::SqliteRateLimitStore;
pub use rate_limiter::SqliteRateLimiterRepository;
use sqlx::SqlitePool;
#[cfg(feature = "teams")]
pub use teams::{
    SqliteTeamInvitationRepository, SqliteTeamMemberPermissionRepository,
    SqliteTeamMembershipRepository, SqliteTeamRepository, SqliteUserTeamContextRepository,
};
pub use token::SqliteTokenRepository;
pub use user::SqliteUserRepository;

/// Creates all `SQLite` repository instances from a connection pool.
///
/// Returns the core repositories needed for authentication.
/// For audit logging, enable the `audit_log` feature and create
/// `SqliteAuditLogRepository` manually.
pub fn create_repositories(
    pool: SqlitePool,
) -> (
    SqliteUserRepository,
    SqliteTokenRepository,
    SqlitePasswordResetRepository,
    SqliteEmailVerificationRepository,
    SqliteRateLimiterRepository,
) {
    (
        SqliteUserRepository::new(pool.clone()),
        SqliteTokenRepository::new(pool.clone()),
        SqlitePasswordResetRepository::new(pool.clone()),
        SqliteEmailVerificationRepository::new(pool.clone()),
        SqliteRateLimiterRepository::new(pool),
    )
}
