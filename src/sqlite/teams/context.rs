//! `SQLite` implementation of [`UserTeamContextRepository`].

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, SqlitePool};

use crate::AuthError;
use crate::teams::{UserTeamContext, UserTeamContextRepository};

/// `SQLite`-backed user team context repository.
#[derive(Clone)]
pub struct SqliteUserTeamContextRepository {
    pool: SqlitePool,
}

impl SqliteUserTeamContextRepository {
    /// Create a new repository with the given connection pool.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[derive(FromRow)]
struct ContextRecord {
    user_id: i64,
    current_team_id: i64,
    updated_at: DateTime<Utc>,
}

impl From<ContextRecord> for UserTeamContext {
    fn from(row: ContextRecord) -> Self {
        UserTeamContext {
            user_id: row.user_id as u64,
            current_team_id: row.current_team_id as u64,
            updated_at: row.updated_at,
        }
    }
}

#[async_trait]
impl UserTeamContextRepository for SqliteUserTeamContextRepository {
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn get_context(&self, user_id: u64) -> Result<Option<UserTeamContext>, AuthError> {
        let row: Option<ContextRecord> = sqlx::query_as(
            "SELECT user_id, current_team_id, updated_at FROM user_team_contexts WHERE user_id = ?",
        )
        .bind(user_id as i64)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"get_team_context\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(row.map(Into::into))
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn set_current_team(
        &self,
        user_id: u64,
        team_id: u64,
    ) -> Result<UserTeamContext, AuthError> {
        let now = Utc::now();

        let row: ContextRecord = sqlx::query_as(
            r"
            INSERT INTO user_team_contexts (user_id, current_team_id)
            VALUES (?, ?)
            ON CONFLICT (user_id)
            DO UPDATE SET current_team_id = ?, updated_at = ?
            RETURNING user_id, current_team_id, updated_at
            ",
        )
        .bind(user_id as i64)
        .bind(team_id as i64)
        .bind(team_id as i64)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"set_current_team\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(row.into())
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn clear_context(&self, user_id: u64) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM user_team_contexts WHERE user_id = ?")
            .bind(user_id as i64)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"clear_team_context\", error=\"{e}\"");
                AuthError::DatabaseError(e.to_string())
            })?;

        Ok(())
    }
}
