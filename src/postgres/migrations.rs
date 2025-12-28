//! Feature-gated database migrations.
//!
//! This module provides functions to run migrations for specific features.
//! Only migrations for enabled features are compiled into the binary.
//!
//! # Example
//!
//! ```rust,ignore
//! use enclave::postgres::migrations;
//! use sqlx::PgPool;
//!
//! async fn setup_database(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
//!     // Run only core migrations
//!     migrations::run_core(pool).await?;
//!
//!     // Or run all migrations for enabled features
//!     migrations::run_all(pool).await?;
//!     Ok(())
//! }
//! ```

use sqlx::PgPool;

/// Runs core authentication migrations.
///
/// This includes tables for:
/// - `users`
/// - `access_tokens`
/// - `password_reset_tokens`
/// - `email_verification_tokens`
///
/// These migrations are required for basic authentication functionality.
pub async fn run_core(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations/core").run(pool).await
}

/// Runs rate limiting migrations.
///
/// This includes tables for:
/// - `login_attempts`
/// - `rate_limits`
///
/// Required when using the `rate_limit` feature.
#[cfg(feature = "rate_limit")]
pub async fn run_rate_limit(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations/rate_limit").run(pool).await
}

/// Runs audit logging migrations.
///
/// This includes tables for:
/// - `audit_logs`
///
/// Required when using the `audit_log` feature.
#[cfg(feature = "audit_log")]
pub async fn run_audit_log(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations/audit_log").run(pool).await
}

/// Runs teams migrations.
///
/// This includes tables for:
/// - `teams`
/// - `team_memberships`
/// - `team_invitations`
/// - `team_member_permissions`
/// - `user_team_contexts`
///
/// Required when using the `teams` feature.
#[cfg(feature = "teams")]
pub async fn run_teams(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations/teams").run(pool).await
}

/// Runs magic link migrations.
///
/// This includes tables for:
/// - `magic_link_tokens`
///
/// Required when using the `magic_link` feature.
#[cfg(feature = "magic_link")]
pub async fn run_magic_link(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations/magic_link").run(pool).await
}

/// Runs all migrations for enabled features.
///
/// This is a convenience function that runs migrations in the correct order
/// for all features that are currently enabled at compile time.
///
/// The order is:
/// 1. Core (always)
/// 2. Rate limit (if `rate_limit` feature enabled)
/// 3. Audit log (if `audit_log` feature enabled)
/// 4. Magic link (if `magic_link` feature enabled)
/// 5. Teams (if `teams` feature enabled)
pub async fn run_all(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    run_core(pool).await?;

    #[cfg(feature = "rate_limit")]
    run_rate_limit(pool).await?;

    #[cfg(feature = "audit_log")]
    run_audit_log(pool).await?;

    #[cfg(feature = "magic_link")]
    run_magic_link(pool).await?;

    #[cfg(feature = "teams")]
    run_teams(pool).await?;

    Ok(())
}
