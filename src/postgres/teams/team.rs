use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};

use crate::AuthError;
use crate::teams::{CreateTeam, Team, TeamRepository};

#[derive(Clone)]
pub struct PostgresTeamRepository {
    pool: PgPool,
}

impl PostgresTeamRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(FromRow)]
struct TeamRecord {
    id: i64,
    name: String,
    slug: String,
    owner_id: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<TeamRecord> for Team {
    fn from(row: TeamRecord) -> Self {
        Team {
            id: row.id as u64,
            name: row.name,
            slug: row.slug,
            owner_id: row.owner_id as u64,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[async_trait]
impl TeamRepository for PostgresTeamRepository {
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn create(&self, data: CreateTeam) -> Result<Team, AuthError> {
        let row: TeamRecord = sqlx::query_as(
            r"
            INSERT INTO teams (name, slug, owner_id)
            VALUES ($1, $2, $3)
            RETURNING id, name, slug, owner_id, created_at, updated_at
            ",
        )
        .bind(&data.name)
        .bind(&data.slug)
        .bind(data.owner_id as i64)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"create_team\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(row.into())
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn find_by_id(&self, id: u64) -> Result<Option<Team>, AuthError> {
        let row: Option<TeamRecord> = sqlx::query_as(
            "SELECT id, name, slug, owner_id, created_at, updated_at FROM teams WHERE id = $1",
        )
        .bind(id as i64)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"find_team_by_id\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(row.map(Into::into))
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn find_by_slug(&self, slug: &str) -> Result<Option<Team>, AuthError> {
        let row: Option<TeamRecord> = sqlx::query_as(
            "SELECT id, name, slug, owner_id, created_at, updated_at FROM teams WHERE slug = $1",
        )
        .bind(slug)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"find_team_by_slug\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(row.map(Into::into))
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn update(
        &self,
        id: u64,
        name: Option<&str>,
        slug: Option<&str>,
    ) -> Result<Team, AuthError> {
        let row: TeamRecord = match (name, slug) {
            (Some(n), Some(s)) => {
                sqlx::query_as(
                    r"
                    UPDATE teams SET name = $1, slug = $2, updated_at = NOW()
                    WHERE id = $3
                    RETURNING id, name, slug, owner_id, created_at, updated_at
                    ",
                )
                .bind(n)
                .bind(s)
                .bind(id as i64)
                .fetch_one(&self.pool)
                .await
            }
            (Some(n), None) => {
                sqlx::query_as(
                    r"
                    UPDATE teams SET name = $1, updated_at = NOW()
                    WHERE id = $2
                    RETURNING id, name, slug, owner_id, created_at, updated_at
                    ",
                )
                .bind(n)
                .bind(id as i64)
                .fetch_one(&self.pool)
                .await
            }
            (None, Some(s)) => {
                sqlx::query_as(
                    r"
                    UPDATE teams SET slug = $1, updated_at = NOW()
                    WHERE id = $2
                    RETURNING id, name, slug, owner_id, created_at, updated_at
                    ",
                )
                .bind(s)
                .bind(id as i64)
                .fetch_one(&self.pool)
                .await
            }
            (None, None) => {
                sqlx::query_as(
                    "SELECT id, name, slug, owner_id, created_at, updated_at FROM teams WHERE id = $1",
                )
                .bind(id as i64)
                .fetch_one(&self.pool)
                .await
            }
        }
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AuthError::NotFound,
            _ => {
                log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"update_team\", error=\"{e}\"");
                AuthError::DatabaseError(e.to_string())
            }
        })?;

        Ok(row.into())
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn delete(&self, id: u64) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM teams WHERE id = $1")
            .bind(id as i64)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"delete_team\", error=\"{e}\"");
                AuthError::DatabaseError(e.to_string())
            })?;

        Ok(())
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn find_by_owner(&self, owner_id: u64) -> Result<Vec<Team>, AuthError> {
        let rows: Vec<TeamRecord> = sqlx::query_as(
            "SELECT id, name, slug, owner_id, created_at, updated_at FROM teams WHERE owner_id = $1 ORDER BY created_at DESC",
        )
        .bind(owner_id as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"find_teams_by_owner\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn transfer_ownership(&self, team_id: u64, new_owner_id: u64) -> Result<Team, AuthError> {
        let row: TeamRecord = sqlx::query_as(
            r"
            UPDATE teams SET owner_id = $1, updated_at = NOW()
            WHERE id = $2
            RETURNING id, name, slug, owner_id, created_at, updated_at
            ",
        )
        .bind(new_owner_id as i64)
        .bind(team_id as i64)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AuthError::NotFound,
            _ => {
                log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"transfer_team_ownership\", error=\"{e}\"");
                AuthError::DatabaseError(e.to_string())
            }
        })?;

        Ok(row.into())
    }
}
