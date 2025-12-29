use sqlx::{Executor, SqlitePool};

const CORE_MIGRATIONS: &[(&str, &str)] = &[
    (
        "20241220000001_create_users_table",
        include_str!("../../migrations/sqlite/core/20241220000001_create_users_table.sql"),
    ),
    (
        "20241220000002_create_access_tokens_table",
        include_str!("../../migrations/sqlite/core/20241220000002_create_access_tokens_table.sql"),
    ),
    (
        "20241220000003_create_password_reset_tokens_table",
        include_str!(
            "../../migrations/sqlite/core/20241220000003_create_password_reset_tokens_table.sql"
        ),
    ),
    (
        "20241220000004_create_email_verification_tokens_table",
        include_str!(
            "../../migrations/sqlite/core/20241220000004_create_email_verification_tokens_table.sql"
        ),
    ),
];

#[cfg(feature = "rate_limit")]
const RATE_LIMIT_MIGRATIONS: &[(&str, &str)] = &[
    (
        "20241220000005_create_login_attempts_table",
        include_str!(
            "../../migrations/sqlite/rate_limit/20241220000005_create_login_attempts_table.sql"
        ),
    ),
    (
        "20241223000001_create_rate_limits_table",
        include_str!(
            "../../migrations/sqlite/rate_limit/20241223000001_create_rate_limits_table.sql"
        ),
    ),
];

#[cfg(feature = "audit_log")]
const AUDIT_LOG_MIGRATIONS: &[(&str, &str)] = &[(
    "20241220000006_create_audit_logs_table",
    include_str!("../../migrations/sqlite/audit_log/20241220000006_create_audit_logs_table.sql"),
)];

#[cfg(feature = "magic_link")]
const MAGIC_LINK_MIGRATIONS: &[(&str, &str)] = &[(
    "20241227000001_create_magic_link_tokens_table",
    include_str!(
        "../../migrations/sqlite/magic_link/20241227000001_create_magic_link_tokens_table.sql"
    ),
)];

#[cfg(feature = "teams")]
const TEAMS_MIGRATIONS: &[(&str, &str)] = &[
    (
        "20241227000002_create_teams_table",
        include_str!("../../migrations/sqlite/teams/20241227000002_create_teams_table.sql"),
    ),
    (
        "20241227000003_create_team_memberships_table",
        include_str!(
            "../../migrations/sqlite/teams/20241227000003_create_team_memberships_table.sql"
        ),
    ),
    (
        "20241227000004_create_team_invitations_table",
        include_str!(
            "../../migrations/sqlite/teams/20241227000004_create_team_invitations_table.sql"
        ),
    ),
    (
        "20241227000005_create_team_member_permissions_table",
        include_str!(
            "../../migrations/sqlite/teams/20241227000005_create_team_member_permissions_table.sql"
        ),
    ),
    (
        "20241227000006_create_user_team_contexts_table",
        include_str!(
            "../../migrations/sqlite/teams/20241227000006_create_user_team_contexts_table.sql"
        ),
    ),
];

pub async fn run(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    pool.execute(
        r"
        CREATE TABLE IF NOT EXISTS _enclave_migrations (
            name TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        )
        ",
    )
    .await?;

    run_migrations(pool, CORE_MIGRATIONS).await?;

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

async fn run_migrations(pool: &SqlitePool, migrations: &[(&str, &str)]) -> Result<(), sqlx::Error> {
    for (name, sql) in migrations {
        let applied: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM _enclave_migrations WHERE name = ?)")
                .bind(*name)
                .fetch_one(pool)
                .await?;

        if !applied {
            // sqlite doesn't support multiple statements in one execute,
            // naive splitting will fail if semicolons appear within string literals
            for statement in sql.split(';') {
                let trimmed = statement.trim();
                if !trimmed.is_empty() {
                    pool.execute(trimmed).await?;
                }
            }

            sqlx::query("INSERT INTO _enclave_migrations (name) VALUES (?)")
                .bind(*name)
                .execute(pool)
                .await?;
        }
    }
    Ok(())
}
