//! `PostgreSQL` implementation of [`TeamInvitationRepository`].

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};

use crate::teams::{CreateInvitation, TeamInvitation, TeamInvitationRepository};
use crate::AuthError;

/// PostgreSQL-backed team invitation repository.
#[derive(Clone)]
pub struct PostgresTeamInvitationRepository {
    pool: PgPool,
}

impl PostgresTeamInvitationRepository {
    /// Create a new repository with the given connection pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(FromRow)]
struct InvitationRecord {
    id: i32,
    team_id: i32,
    email: String,
    role: String,
    token_hash: String,
    invited_by: i32,
    expires_at: DateTime<Utc>,
    accepted_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl From<InvitationRecord> for TeamInvitation {
    fn from(row: InvitationRecord) -> Self {
        TeamInvitation {
            id: row.id,
            team_id: row.team_id,
            email: row.email,
            role: row.role,
            token_hash: row.token_hash,
            invited_by: row.invited_by,
            expires_at: row.expires_at,
            accepted_at: row.accepted_at,
            created_at: row.created_at,
        }
    }
}

#[async_trait]
impl TeamInvitationRepository for PostgresTeamInvitationRepository {
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn create(&self, data: CreateInvitation) -> Result<TeamInvitation, AuthError> {
        let row: InvitationRecord = sqlx::query_as(
            r"
            INSERT INTO team_invitations (team_id, email, role, token_hash, invited_by, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, team_id, email, role, token_hash, invited_by, expires_at, accepted_at, created_at
            ",
        )
        .bind(data.team_id)
        .bind(&data.email)
        .bind(&data.role)
        .bind(&data.token_hash)
        .bind(data.invited_by)
        .bind(data.expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"create_invitation\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(row.into())
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn find_by_id(&self, id: i32) -> Result<Option<TeamInvitation>, AuthError> {
        let row: Option<InvitationRecord> = sqlx::query_as(
            "SELECT id, team_id, email, role, token_hash, invited_by, expires_at, accepted_at, created_at FROM team_invitations WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"find_invitation_by_id\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(row.map(Into::into))
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<TeamInvitation>, AuthError> {
        let row: Option<InvitationRecord> = sqlx::query_as(
            "SELECT id, team_id, email, role, token_hash, invited_by, expires_at, accepted_at, created_at FROM team_invitations WHERE token_hash = $1",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"find_invitation_by_token_hash\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(row.map(Into::into))
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn find_pending_by_team(&self, team_id: i32) -> Result<Vec<TeamInvitation>, AuthError> {
        let rows: Vec<InvitationRecord> = sqlx::query_as(
            r"
            SELECT id, team_id, email, role, token_hash, invited_by, expires_at, accepted_at, created_at
            FROM team_invitations
            WHERE team_id = $1 AND accepted_at IS NULL AND expires_at > NOW()
            ORDER BY created_at DESC
            ",
        )
        .bind(team_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"find_pending_invitations_by_team\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn find_pending_by_email(&self, email: &str) -> Result<Vec<TeamInvitation>, AuthError> {
        let rows: Vec<InvitationRecord> = sqlx::query_as(
            r"
            SELECT id, team_id, email, role, token_hash, invited_by, expires_at, accepted_at, created_at
            FROM team_invitations
            WHERE email = $1 AND accepted_at IS NULL AND expires_at > NOW()
            ORDER BY created_at DESC
            ",
        )
        .bind(email)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"find_pending_invitations_by_email\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn mark_accepted(&self, id: i32) -> Result<TeamInvitation, AuthError> {
        let row: InvitationRecord = sqlx::query_as(
            r"
            UPDATE team_invitations SET accepted_at = NOW()
            WHERE id = $1
            RETURNING id, team_id, email, role, token_hash, invited_by, expires_at, accepted_at, created_at
            ",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AuthError::NotFound,
            _ => {
                log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"mark_invitation_accepted\", error=\"{e}\"");
                AuthError::DatabaseError(e.to_string())
            }
        })?;

        Ok(row.into())
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn delete(&self, id: i32) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM team_invitations WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"delete_invitation\", error=\"{e}\"");
                AuthError::DatabaseError(e.to_string())
            })?;

        Ok(())
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn delete_expired(&self) -> Result<u64, AuthError> {
        let result = sqlx::query("DELETE FROM team_invitations WHERE expires_at < NOW()")
            .execute(&self.pool)
            .await
            .map_err(|e| {
                log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"delete_expired_invitations\", error=\"{e}\"");
                AuthError::DatabaseError(e.to_string())
            })?;

        Ok(result.rows_affected())
    }
}
