//! `PostgreSQL` implementation of [`UserTeamContextRepository`].

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};

use crate::AuthError;
use crate::teams::{UserTeamContext, UserTeamContextRepository};

/// PostgreSQL-backed user team context repository.
#[derive(Clone)]
pub struct PostgresUserTeamContextRepository {
    pool: PgPool,
}

impl PostgresUserTeamContextRepository {
    /// Create a new repository with the given connection pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(FromRow)]
struct ContextRecord {
    user_id: i32,
    current_team_id: i32,
    updated_at: DateTime<Utc>,
}

impl From<ContextRecord> for UserTeamContext {
    fn from(row: ContextRecord) -> Self {
        UserTeamContext {
            user_id: row.user_id,
            current_team_id: row.current_team_id,
            updated_at: row.updated_at,
        }
    }
}

#[async_trait]
impl UserTeamContextRepository for PostgresUserTeamContextRepository {
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn get_context(&self, user_id: i32) -> Result<Option<UserTeamContext>, AuthError> {
        let row: Option<ContextRecord> = sqlx::query_as(
            "SELECT user_id, current_team_id, updated_at FROM user_team_contexts WHERE user_id = $1",
        )
        .bind(user_id)
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
        user_id: i32,
        team_id: i32,
    ) -> Result<UserTeamContext, AuthError> {
        let row: ContextRecord = sqlx::query_as(
            r"
            INSERT INTO user_team_contexts (user_id, current_team_id)
            VALUES ($1, $2)
            ON CONFLICT (user_id)
            DO UPDATE SET current_team_id = $2, updated_at = NOW()
            RETURNING user_id, current_team_id, updated_at
            ",
        )
        .bind(user_id)
        .bind(team_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"set_current_team\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(row.into())
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn clear_context(&self, user_id: i32) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM user_team_contexts WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"clear_team_context\", error=\"{e}\"");
                AuthError::DatabaseError(e.to_string())
            })?;

        Ok(())
    }
}
