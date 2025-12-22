use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};

use crate::{AuthError, User, UserRepository};

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

impl From<UserRecord> for User {
    fn from(row: UserRecord) -> Self {
        User {
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
    async fn find_user_by_id(&self, id: i32) -> Result<Option<User>, AuthError> {
        let row: Option<UserRecord> = sqlx::query_as(
            "SELECT id, email, name, hashed_password, email_verified_at, created_at, updated_at FROM users WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(row.map(Into::into))
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, AuthError> {
        let row: Option<UserRecord> = sqlx::query_as(
            "SELECT id, email, name, hashed_password, email_verified_at, created_at, updated_at FROM users WHERE email = $1"
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(row.map(Into::into))
    }

    async fn create_user(&self, email: &str, hashed_password: &str) -> Result<User, AuthError> {
        let row: UserRecord = sqlx::query_as(
            "INSERT INTO users (email, hashed_password) VALUES ($1, $2) RETURNING id, email, name, hashed_password, email_verified_at, created_at, updated_at"
        )
        .bind(email)
        .bind(hashed_password)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(row.into())
    }

    async fn update_password(&self, user_id: i32, hashed_password: &str) -> Result<(), AuthError> {
        let result =
            sqlx::query("UPDATE users SET hashed_password = $1, updated_at = NOW() WHERE id = $2")
                .bind(hashed_password)
                .bind(user_id)
                .execute(&self.pool)
                .await
                .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AuthError::UserNotFound);
        }

        Ok(())
    }

    async fn verify_email(&self, user_id: i32) -> Result<(), AuthError> {
        let result = sqlx::query(
            "UPDATE users SET email_verified_at = NOW(), updated_at = NOW() WHERE id = $1",
        )
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AuthError::UserNotFound);
        }

        Ok(())
    }

    async fn update_user(&self, user_id: i32, name: &str, email: &str) -> Result<User, AuthError> {
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
            _ => AuthError::DatabaseError(e.to_string()),
        })?;

        Ok(row.into())
    }

    async fn delete_user(&self, user_id: i32) -> Result<(), AuthError> {
        let result = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AuthError::UserNotFound);
        }

        Ok(())
    }
}
