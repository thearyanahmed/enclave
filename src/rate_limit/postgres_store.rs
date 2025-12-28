use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;

use super::store::{RateLimitInfo, RateLimitStore};
use crate::AuthError;

/// `PostgreSQL`-backed rate limit store.
///
/// Suitable for distributed deployments where multiple instances
/// need to share rate limit state.
///
/// # Table Schema
///
/// This store expects a table with the following schema:
///
/// ```sql
/// CREATE TABLE rate_limits (
///     key VARCHAR(255) PRIMARY KEY,
///     attempts INTEGER NOT NULL DEFAULT 1,
///     reset_at TIMESTAMPTZ NOT NULL,
///     created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
///     updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
/// );
///
/// CREATE INDEX idx_rate_limits_reset_at ON rate_limits(reset_at);
/// ```
#[derive(Clone)]
pub struct PostgresRateLimitStore {
    pool: PgPool,
}

impl PostgresRateLimitStore {
    /// Creates a new `PostgreSQL` rate limit store.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Cleans up expired entries.
    ///
    /// Call this periodically to prevent table growth.
    pub async fn cleanup_expired(&self) -> Result<u64, AuthError> {
        let result = sqlx::query("DELETE FROM rate_limits WHERE reset_at < NOW()")
            .execute(&self.pool)
            .await
            .map_err(|e| {
                log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"cleanup_expired_rate_limits\", error=\"{e}\"");
                AuthError::DatabaseError(e.to_string())
            })?;

        Ok(result.rows_affected())
    }
}

#[derive(sqlx::FromRow)]
struct RateLimitRow {
    attempts: i32,
    reset_at: DateTime<Utc>,
}

#[async_trait]
impl RateLimitStore for PostgresRateLimitStore {
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn increment(&self, key: &str, window_secs: u64) -> Result<RateLimitInfo, AuthError> {
        let window_interval = format!("{window_secs} seconds");

        // Use UPSERT to atomically increment or create
        let row: RateLimitRow = sqlx::query_as(
            r"
            INSERT INTO rate_limits (key, attempts, reset_at, updated_at)
            VALUES ($1, 1, NOW() + $2::interval, NOW())
            ON CONFLICT (key) DO UPDATE SET
                attempts = CASE
                    WHEN rate_limits.reset_at <= NOW() THEN 1
                    ELSE rate_limits.attempts + 1
                END,
                reset_at = CASE
                    WHEN rate_limits.reset_at <= NOW() THEN NOW() + $2::interval
                    ELSE rate_limits.reset_at
                END,
                updated_at = NOW()
            RETURNING attempts, reset_at
            ",
        )
        .bind(key)
        .bind(&window_interval)
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
            sqlx::query_as("SELECT attempts, reset_at FROM rate_limits WHERE key = $1")
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
        sqlx::query("DELETE FROM rate_limits WHERE key = $1")
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
