use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;

use crate::{AuthError, RateLimiterRepository};

#[derive(Clone)]
pub struct PostgresRateLimiterRepository {
    pool: PgPool,
}

impl PostgresRateLimiterRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RateLimiterRepository for PostgresRateLimiterRepository {
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, email, ip_address), err))]
    async fn record_attempt(
        &self,
        email: &str,
        success: bool,
        ip_address: Option<&str>,
    ) -> Result<(), AuthError> {
        sqlx::query("INSERT INTO login_attempts (email, success, ip_address) VALUES ($1, $2, $3)")
            .bind(email)
            .bind(success)
            .bind(ip_address)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, email), err))]
    async fn get_recent_failed_attempts(
        &self,
        email: &str,
        since: DateTime<Utc>,
    ) -> Result<u32, AuthError> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM login_attempts WHERE email = $1 AND success = false AND attempted_at >= $2"
        )
        .bind(email)
        .bind(since)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(u32::try_from(row.0).unwrap_or(u32::MAX))
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, email), err))]
    async fn clear_attempts(&self, email: &str) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM login_attempts WHERE email = $1")
            .bind(email)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(())
    }
}
