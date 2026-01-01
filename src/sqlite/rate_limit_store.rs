use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use sqlx::SqlitePool;

use crate::AuthError;
use crate::rate_limit::{RateLimitInfo, RateLimitStore};

/// `SQLite`-backed rate limit store.
///
/// Suitable for single-instance deployments or testing.
///
/// # Table Schema
///
/// This store expects a table with the following schema:
///
/// ```sql
/// CREATE TABLE rate_limits (
///     key TEXT PRIMARY KEY,
///     attempts INTEGER NOT NULL DEFAULT 1,
///     reset_at TEXT NOT NULL,
///     created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
///     updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
/// );
///
/// CREATE INDEX idx_rate_limits_reset_at ON rate_limits(reset_at);
/// ```
#[derive(Clone)]
pub struct SqliteRateLimitStore {
    pool: SqlitePool,
}

impl SqliteRateLimitStore {
    /// Creates a new `SQLite` rate limit store.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Cleans up expired entries.
    ///
    /// Call this periodically to prevent table growth.
    pub async fn cleanup_expired(&self) -> Result<i64, AuthError> {
        let now = Utc::now();
        let result = sqlx::query("DELETE FROM rate_limits WHERE reset_at < ?")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"cleanup_expired_rate_limits\", error=\"{e}\"");
                AuthError::DatabaseError(e.to_string())
            })?;

        Ok(result.rows_affected() as i64)
    }
}

#[derive(sqlx::FromRow)]
struct RateLimitRow {
    attempts: i32,
    reset_at: DateTime<Utc>,
}

#[async_trait]
impl RateLimitStore for SqliteRateLimitStore {
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn increment(&self, key: &str, window_secs: i64) -> Result<RateLimitInfo, AuthError> {
        let now = Utc::now();
        let new_reset_at = now + Duration::seconds(window_secs);

        // Use UPSERT to atomically increment or create
        // SQLite 3.24.0+ supports ON CONFLICT ... DO UPDATE
        let row: RateLimitRow = sqlx::query_as(
            r"
            INSERT INTO rate_limits (key, attempts, reset_at, updated_at)
            VALUES (?, 1, ?, ?)
            ON CONFLICT (key) DO UPDATE SET
                attempts = CASE
                    WHEN rate_limits.reset_at <= ? THEN 1
                    ELSE rate_limits.attempts + 1
                END,
                reset_at = CASE
                    WHEN rate_limits.reset_at <= ? THEN ?
                    ELSE rate_limits.reset_at
                END,
                updated_at = ?
            RETURNING attempts, reset_at
            ",
        )
        .bind(key)
        .bind(new_reset_at)
        .bind(now)
        .bind(now)
        .bind(now)
        .bind(new_reset_at)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"rate_limit_increment\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(RateLimitInfo {
            attempts: u32::try_from(row.attempts).unwrap_or(u32::MAX),
            reset_at: row.reset_at,
        })
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn get(&self, key: &str) -> Result<Option<RateLimitInfo>, AuthError> {
        let row: Option<RateLimitRow> =
            sqlx::query_as("SELECT attempts, reset_at FROM rate_limits WHERE key = ?")
                .bind(key)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| {
                    log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"rate_limit_get\", error=\"{e}\"");
                    AuthError::DatabaseError(e.to_string())
                })?;

        Ok(row.map(|r| RateLimitInfo {
            attempts: u32::try_from(r.attempts).unwrap_or(u32::MAX),
            reset_at: r.reset_at,
        }))
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn reset(&self, key: &str) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM rate_limits WHERE key = ?")
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"rate_limit_reset\", error=\"{e}\"");
                AuthError::DatabaseError(e.to_string())
            })?;

        Ok(())
    }
}
