//! `PostgreSQL` implementation of [`TeamMemberPermissionRepository`].

use std::marker::PhantomData;

use async_trait::async_trait;
use sqlx::{FromRow, PgPool};

use crate::AuthError;
use crate::teams::{Action, PermissionSet, Resource, TeamMemberPermissionRepository};

/// PostgreSQL-backed team member permission repository.
///
/// Permissions are stored as JSON in the database for flexibility.
/// The repository is generic over Resource and Action types.
#[derive(Clone)]
pub struct PostgresTeamMemberPermissionRepository<R, A>
where
    R: Resource,
    A: Action,
{
    pool: PgPool,
    _phantom: PhantomData<(R, A)>,
}

impl<R, A> PostgresTeamMemberPermissionRepository<R, A>
where
    R: Resource,
    A: Action,
{
    /// Create a new repository with the given connection pool.
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            _phantom: PhantomData,
        }
    }
}

#[derive(FromRow)]
struct PermissionRecord {
    permissions: serde_json::Value,
}

#[async_trait]
impl<R, A> TeamMemberPermissionRepository<R, A> for PostgresTeamMemberPermissionRepository<R, A>
where
    R: Resource,
    A: Action,
{
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn get_permissions(
        &self,
        team_id: i32,
        user_id: i32,
    ) -> Result<PermissionSet<R, A>, AuthError> {
        let row: Option<PermissionRecord> = sqlx::query_as(
            "SELECT permissions FROM team_member_permissions WHERE team_id = $1 AND user_id = $2",
        )
        .bind(team_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"get_permissions\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        match row {
            Some(record) => {
                let json_str = record.permissions.to_string();
                PermissionSet::from_json(&json_str).ok_or_else(|| {
                    log::error!(target: "enclave_auth", "msg=\"invalid permission format\", operation=\"get_permissions\"");
                    AuthError::Internal("invalid permission format in database".into())
                })
            }
            None => Ok(PermissionSet::new()),
        }
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, permissions), err))]
    async fn set_permissions(
        &self,
        team_id: i32,
        user_id: i32,
        permissions: &PermissionSet<R, A>,
    ) -> Result<(), AuthError> {
        let json_str = permissions.to_json();
        let json_value: serde_json::Value = serde_json::from_str(&json_str).map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"json serialization error\", operation=\"set_permissions\", error=\"{e}\"");
            AuthError::Internal(e.to_string())
        })?;

        sqlx::query(
            r"
            INSERT INTO team_member_permissions (team_id, user_id, permissions)
            VALUES ($1, $2, $3)
            ON CONFLICT (team_id, user_id)
            DO UPDATE SET permissions = $3, updated_at = NOW()
            ",
        )
        .bind(team_id)
        .bind(user_id)
        .bind(json_value)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"set_permissions\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(skip(self, resource, action), err)
    )]
    async fn grant_permission(
        &self,
        team_id: i32,
        user_id: i32,
        resource: R,
        action: A,
    ) -> Result<(), AuthError> {
        let mut perms = self.get_permissions(team_id, user_id).await?;
        perms.grant(resource, action);
        self.set_permissions(team_id, user_id, &perms).await
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(skip(self, resource, action), err)
    )]
    async fn revoke_permission(
        &self,
        team_id: i32,
        user_id: i32,
        resource: &R,
        action: &A,
    ) -> Result<(), AuthError> {
        let mut perms = self.get_permissions(team_id, user_id).await?;
        perms.revoke(resource, action);
        self.set_permissions(team_id, user_id, &perms).await
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(skip(self, resource, action), err)
    )]
    async fn has_permission(
        &self,
        team_id: i32,
        user_id: i32,
        resource: &R,
        action: &A,
    ) -> Result<bool, AuthError> {
        let perms = self.get_permissions(team_id, user_id).await?;
        Ok(perms.can(resource, action))
    }
}
