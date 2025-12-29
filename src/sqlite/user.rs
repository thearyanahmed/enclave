use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, SqlitePool};

use crate::{AuthError, AuthUser, UserRepository};

#[derive(Clone)]
pub struct SqliteUserRepository {
    pool: SqlitePool,
}

impl SqliteUserRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[derive(FromRow)]
struct UserRecord {
    id: i64,
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
            id: row.id as u64,
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
impl UserRepository for SqliteUserRepository {
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn find_user_by_id(&self, id: u64) -> Result<Option<AuthUser>, AuthError> {
        let row: Option<UserRecord> = sqlx::query_as(
            "SELECT id, email, name, hashed_password, email_verified_at, created_at, updated_at FROM users WHERE id = ?"
        )
        .bind(id as i64)
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
            "SELECT id, email, name, hashed_password, email_verified_at, created_at, updated_at FROM users WHERE email = ?"
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
        let now = Utc::now();
        let row: UserRecord = sqlx::query_as(
            "INSERT INTO users (email, hashed_password, created_at, updated_at) VALUES (?, ?, ?, ?) RETURNING id, email, name, hashed_password, email_verified_at, created_at, updated_at"
        )
        .bind(email)
        .bind(hashed_password)
        .bind(now)
        .bind(now)
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
    async fn update_password(&self, user_id: u64, hashed_password: &str) -> Result<(), AuthError> {
        let now = Utc::now();
        let result = sqlx::query("UPDATE users SET hashed_password = ?, updated_at = ? WHERE id = ?")
            .bind(hashed_password)
            .bind(now)
            .bind(user_id as i64)
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
    async fn verify_email(&self, user_id: u64) -> Result<(), AuthError> {
        let now = Utc::now();
        let result = sqlx::query("UPDATE users SET email_verified_at = ?, updated_at = ? WHERE id = ?")
            .bind(now)
            .bind(now)
            .bind(user_id as i64)
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
        user_id: u64,
        name: &str,
        email: &str,
    ) -> Result<AuthUser, AuthError> {
        let now = Utc::now();
        let row: UserRecord = sqlx::query_as(
            "UPDATE users SET name = ?, email = ?, updated_at = ? WHERE id = ? RETURNING id, email, name, hashed_password, email_verified_at, created_at, updated_at"
        )
        .bind(name)
        .bind(email)
        .bind(now)
        .bind(user_id as i64)
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
    async fn delete_user(&self, user_id: u64) -> Result<(), AuthError> {
        let result = sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(user_id as i64)
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
