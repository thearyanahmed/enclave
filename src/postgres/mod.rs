mod audit_log;
mod email_verification;
mod password_reset;
mod rate_limiter;
mod token;
mod user;

pub use audit_log::PostgresAuditLogRepository;
pub use email_verification::PostgresEmailVerificationRepository;
pub use password_reset::PostgresPasswordResetRepository;
pub use rate_limiter::PostgresRateLimiterRepository;
pub use token::PostgresTokenRepository;
pub use user::PostgresUserRepository;

use sqlx::PgPool;

/// Creates all Postgres repository instances from a connection pool.
pub fn create_repositories(
    pool: PgPool,
) -> (
    PostgresUserRepository,
    PostgresTokenRepository,
    PostgresPasswordResetRepository,
    PostgresEmailVerificationRepository,
    PostgresRateLimiterRepository,
    PostgresAuditLogRepository,
) {
    (
        PostgresUserRepository::new(pool.clone()),
        PostgresTokenRepository::new(pool.clone()),
        PostgresPasswordResetRepository::new(pool.clone()),
        PostgresEmailVerificationRepository::new(pool.clone()),
        PostgresRateLimiterRepository::new(pool.clone()),
        PostgresAuditLogRepository::new(pool),
    )
}
