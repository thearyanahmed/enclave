//! `SQLite` implementation of [`TeamMembershipRepository`].

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, SqlitePool};

use crate::teams::{CreateMembership, TeamMembership, TeamMembershipRepository};
use crate::AuthError;

/// `SQLite`-backed team membership repository.
#[derive(Clone)]
pub struct SqliteTeamMembershipRepository {
    pool: SqlitePool,
}

impl SqliteTeamMembershipRepository {
    /// Create a new repository with the given connection pool.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[derive(FromRow)]
struct MembershipRecord {
    id: i32,
    team_id: i32,
    user_id: i32,
    role: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<MembershipRecord> for TeamMembership {
    fn from(row: MembershipRecord) -> Self {
        TeamMembership {
            id: row.id,
            team_id: row.team_id,
            user_id: row.user_id,
            role: row.role,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[async_trait]
impl TeamMembershipRepository for SqliteTeamMembershipRepository {
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn create(&self, data: CreateMembership) -> Result<TeamMembership, AuthError> {
        let row: MembershipRecord = sqlx::query_as(
            r"
            INSERT INTO team_memberships (team_id, user_id, role)
            VALUES (?, ?, ?)
            RETURNING id, team_id, user_id, role, created_at, updated_at
            ",
        )
        .bind(data.team_id)
        .bind(data.user_id)
        .bind(&data.role)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"create_membership\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(row.into())
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn find_by_id(&self, id: i32) -> Result<Option<TeamMembership>, AuthError> {
        let row: Option<MembershipRecord> = sqlx::query_as(
            "SELECT id, team_id, user_id, role, created_at, updated_at FROM team_memberships WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"find_membership_by_id\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(row.map(Into::into))
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn find_by_team_and_user(
        &self,
        team_id: i32,
        user_id: i32,
    ) -> Result<Option<TeamMembership>, AuthError> {
        let row: Option<MembershipRecord> = sqlx::query_as(
            "SELECT id, team_id, user_id, role, created_at, updated_at FROM team_memberships WHERE team_id = ? AND user_id = ?",
        )
        .bind(team_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"find_membership_by_team_and_user\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(row.map(Into::into))
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn find_by_team(&self, team_id: i32) -> Result<Vec<TeamMembership>, AuthError> {
        let rows: Vec<MembershipRecord> = sqlx::query_as(
            "SELECT id, team_id, user_id, role, created_at, updated_at FROM team_memberships WHERE team_id = ? ORDER BY created_at ASC",
        )
        .bind(team_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"find_memberships_by_team\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn find_by_user(&self, user_id: i32) -> Result<Vec<TeamMembership>, AuthError> {
        let rows: Vec<MembershipRecord> = sqlx::query_as(
            "SELECT id, team_id, user_id, role, created_at, updated_at FROM team_memberships WHERE user_id = ? ORDER BY created_at ASC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"find_memberships_by_user\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn update_role(&self, id: i32, role: &str) -> Result<TeamMembership, AuthError> {
        let now = Utc::now();

        let row: MembershipRecord = sqlx::query_as(
            r"
            UPDATE team_memberships SET role = ?, updated_at = ?
            WHERE id = ?
            RETURNING id, team_id, user_id, role, created_at, updated_at
            ",
        )
        .bind(role)
        .bind(now)
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AuthError::NotFound,
            _ => {
                log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"update_membership_role\", error=\"{e}\"");
                AuthError::DatabaseError(e.to_string())
            }
        })?;

        Ok(row.into())
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn delete(&self, id: i32) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM team_memberships WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"delete_membership\", error=\"{e}\"");
                AuthError::DatabaseError(e.to_string())
            })?;

        Ok(())
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn delete_by_team_and_user(&self, team_id: i32, user_id: i32) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM team_memberships WHERE team_id = ? AND user_id = ?")
            .bind(team_id)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"delete_membership_by_team_and_user\", error=\"{e}\"");
                AuthError::DatabaseError(e.to_string())
            })?;

        Ok(())
    }
}
