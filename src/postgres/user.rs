use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};

use crate::{AuthError, AuthUser, UserRepository};

#[derive(Clone)]
pub struct PostgresUserRepository {
    pool: PgPool,
}

impl PostgresUserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(FromRow)]
struct UserRecord {
    id: i32,
    email: String,
    name: String,
    hashed_password: String,
    email_verified_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<UserRecord> for AuthUser {
    fn from(row: UserRecord) -> Self {
        AuthUser {
            id: row.id,
            email: row.email,
            name: row.name,
            hashed_password: row.hashed_password,
            email_verified_at: row.email_verified_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[async_trait]
impl UserRepository for PostgresUserRepository {
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn find_user_by_id(&self, id: i32) -> Result<Option<AuthUser>, AuthError> {
        let row: Option<UserRecord> = sqlx::query_as(
            "SELECT id, email, name, hashed_password, email_verified_at, created_at, updated_at FROM users WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"find_user_by_id\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(row.map(Into::into))
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, email), err))]
    async fn find_user_by_email(&self, email: &str) -> Result<Option<AuthUser>, AuthError> {
        let row: Option<UserRecord> = sqlx::query_as(
            "SELECT id, email, name, hashed_password, email_verified_at, created_at, updated_at FROM users WHERE email = $1"
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"find_user_by_email\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(row.map(Into::into))
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(skip(self, email, hashed_password), err)
    )]
    async fn create_user(&self, email: &str, hashed_password: &str) -> Result<AuthUser, AuthError> {
        let row: UserRecord = sqlx::query_as(
            "INSERT INTO users (email, hashed_password) VALUES ($1, $2) RETURNING id, email, name, hashed_password, email_verified_at, created_at, updated_at"
        )
        .bind(email)
        .bind(hashed_password)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"create_user\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(row.into())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(skip(self, hashed_password), err)
    )]
    async fn update_password(&self, user_id: i32, hashed_password: &str) -> Result<(), AuthError> {
        let result =
            sqlx::query("UPDATE users SET hashed_password = $1, updated_at = NOW() WHERE id = $2")
                .bind(hashed_password)
                .bind(user_id)
                .execute(&self.pool)
                .await
                .map_err(|e| {
                    log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"update_password\", error=\"{e}\"");
                    AuthError::DatabaseError(e.to_string())
                })?;

        if result.rows_affected() == 0 {
            return Err(AuthError::UserNotFound);
        }

        Ok(())
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn verify_email(&self, user_id: i32) -> Result<(), AuthError> {
        let result = sqlx::query(
            "UPDATE users SET email_verified_at = NOW(), updated_at = NOW() WHERE id = $1",
        )
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"verify_email\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        if result.rows_affected() == 0 {
            return Err(AuthError::UserNotFound);
        }

        Ok(())
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, name, email), err))]
    async fn update_user(
        &self,
        user_id: i32,
        name: &str,
        email: &str,
    ) -> Result<AuthUser, AuthError> {
        let row: UserRecord = sqlx::query_as(
            "UPDATE users SET name = $1, email = $2, updated_at = NOW() WHERE id = $3 RETURNING id, email, name, hashed_password, email_verified_at, created_at, updated_at"
        )
        .bind(name)
        .bind(email)
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AuthError::UserNotFound,
            _ => {
                log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"update_user\", error=\"{e}\"");
                AuthError::DatabaseError(e.to_string())
            }
        })?;

        Ok(row.into())
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn delete_user(&self, user_id: i32) -> Result<(), AuthError> {
        let result = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"delete_user\", error=\"{e}\"");
                AuthError::DatabaseError(e.to_string())
            })?;

        if result.rows_affected() == 0 {
            return Err(AuthError::UserNotFound);
        }

        Ok(())
    }
}
