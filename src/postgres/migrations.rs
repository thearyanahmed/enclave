//! Feature-gated database migrations.
//!
//! Migrations are organized by feature and only executed when the feature is enabled.
//! Each feature's migrations are embedded at compile time and run programmatically.
//!
//! # Example
//!
//! ```rust,ignore
//! use enclave::postgres::migrations;
//! use sqlx::PgPool;
//!
//! async fn setup_database(pool: &PgPool) -> Result<(), sqlx::Error> {
//!     migrations::run(pool).await?;
//!     Ok(())
//! }
//! ```

use sqlx::{Executor, PgPool};

/// Core migrations - always required.
const CORE_MIGRATIONS: &[(&str, &str)] = &[
    (
        "20241220000001_create_users_table",
        include_str!("../../migrations/core/20241220000001_create_users_table.sql"),
    ),
    (
        "20241220000002_create_access_tokens_table",
        include_str!("../../migrations/core/20241220000002_create_access_tokens_table.sql"),
    ),
    (
        "20241220000003_create_password_reset_tokens_table",
        include_str!("../../migrations/core/20241220000003_create_password_reset_tokens_table.sql"),
    ),
    (
        "20241220000004_create_email_verification_tokens_table",
        include_str!(
            "../../migrations/core/20241220000004_create_email_verification_tokens_table.sql"
        ),
    ),
    (
        "20241222000001_add_token_metadata_fields",
        include_str!("../../migrations/core/20241222000001_add_token_metadata_fields.sql"),
    ),
];

/// Rate limit migrations.
#[cfg(feature = "rate_limit")]
const RATE_LIMIT_MIGRATIONS: &[(&str, &str)] = &[
    (
        "20241220000005_create_login_attempts_table",
        include_str!("../../migrations/rate_limit/20241220000005_create_login_attempts_table.sql"),
    ),
    (
        "20241223000001_create_rate_limits_table",
        include_str!("../../migrations/rate_limit/20241223000001_create_rate_limits_table.sql"),
    ),
];

/// Audit log migrations.
#[cfg(feature = "audit_log")]
const AUDIT_LOG_MIGRATIONS: &[(&str, &str)] = &[(
    "20241220000006_create_audit_logs_table",
    include_str!("../../migrations/audit_log/20241220000006_create_audit_logs_table.sql"),
)];

/// Magic link migrations.
#[cfg(feature = "magic_link")]
const MAGIC_LINK_MIGRATIONS: &[(&str, &str)] = &[(
    "20241227000001_create_magic_link_tokens_table",
    include_str!("../../migrations/magic_link/20241227000001_create_magic_link_tokens_table.sql"),
)];

/// Teams migrations.
#[cfg(feature = "teams")]
const TEAMS_MIGRATIONS: &[(&str, &str)] = &[
    (
        "20241227000002_create_teams_table",
        include_str!("../../migrations/teams/20241227000002_create_teams_table.sql"),
    ),
    (
        "20241227000003_create_team_memberships_table",
        include_str!("../../migrations/teams/20241227000003_create_team_memberships_table.sql"),
    ),
    (
        "20241227000004_create_team_invitations_table",
        include_str!("../../migrations/teams/20241227000004_create_team_invitations_table.sql"),
    ),
    (
        "20241227000005_create_team_member_permissions_table",
        include_str!(
            "../../migrations/teams/20241227000005_create_team_member_permissions_table.sql"
        ),
    ),
    (
        "20241227000006_create_user_team_contexts_table",
        include_str!("../../migrations/teams/20241227000006_create_user_team_contexts_table.sql"),
    ),
];

/// Runs all database migrations for enabled features.
///
/// Migrations are executed in order and tracked in the `_enclave_migrations` table.
/// Only migrations for enabled features are compiled and executed.
pub async fn run(pool: &PgPool) -> Result<(), sqlx::Error> {
    // Create migrations tracking table
    pool.execute(
        r"
        CREATE TABLE IF NOT EXISTS _enclave_migrations (
            name TEXT PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        ",
    )
    .await?;

    // Run core migrations
    run_migrations(pool, CORE_MIGRATIONS).await?;

    // Run feature-specific migrations
    #[cfg(feature = "rate_limit")]
    run_migrations(pool, RATE_LIMIT_MIGRATIONS).await?;

    #[cfg(feature = "audit_log")]
    run_migrations(pool, AUDIT_LOG_MIGRATIONS).await?;

    #[cfg(feature = "magic_link")]
    run_migrations(pool, MAGIC_LINK_MIGRATIONS).await?;

    #[cfg(feature = "teams")]
    run_migrations(pool, TEAMS_MIGRATIONS).await?;

    Ok(())
}

async fn run_migrations(pool: &PgPool, migrations: &[(&str, &str)]) -> Result<(), sqlx::Error> {
    for (name, sql) in migrations {
        // Check if already applied
        let applied: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM _enclave_migrations WHERE name = $1)")
                .bind(*name)
                .fetch_one(pool)
                .await?;

        if !applied {
            // Run migration
            pool.execute(*sql).await?;

            // Record migration
            sqlx::query("INSERT INTO _enclave_migrations (name) VALUES ($1)")
                .bind(*name)
                .execute(pool)
                .await?;
        }
    }
    Ok(())
}
