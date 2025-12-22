use async_trait::async_trait;
use sqlx::PgPool;

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

#[async_trait]
impl UserRepository for PostgresUserRepository {
    async fn create_user(&self, email: &str, hashed_password: &str) -> Result<User, AuthError> {
        let row = sqlx::query_as!(
            UserRow,
            r#"
            INSERT INTO users (email, hashed_password)
            VALUES ($1, $2)
            RETURNING id, email, name, hashed_password, email_verified_at, created_at, updated_at
            "#,
            email,
            hashed_password
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(row.into())
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, AuthError> {
        let row = sqlx::query_as!(
            UserRow,
            r#"
            SELECT id, email, name, hashed_password, email_verified_at, created_at, updated_at
            FROM users
            WHERE email = $1
            "#,
            email
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(row.map(Into::into))
    }

    async fn find_user_by_id(&self, id: i32) -> Result<Option<User>, AuthError> {
        let row = sqlx::query_as!(
            UserRow,
            r#"
            SELECT id, email, name, hashed_password, email_verified_at, created_at, updated_at
            FROM users
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(row.map(Into::into))
    }

    async fn update_user(&self, user: &User) -> Result<User, AuthError> {
        let row = sqlx::query_as!(
            UserRow,
            r#"
            UPDATE users
            SET email = $1, name = $2, updated_at = NOW()
            WHERE id = $3
            RETURNING id, email, name, hashed_password, email_verified_at, created_at, updated_at
            "#,
            user.email,
            user.name,
            user.id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(row.into())
    }

    async fn update_password(&self, user_id: i32, hashed_password: &str) -> Result<(), AuthError> {
        sqlx::query!(
            r#"
            UPDATE users
            SET hashed_password = $1, updated_at = NOW()
            WHERE id = $2
            "#,
            hashed_password,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn mark_email_verified(&self, user_id: i32) -> Result<(), AuthError> {
        sqlx::query!(
            r#"
            UPDATE users
            SET email_verified_at = NOW(), updated_at = NOW()
            WHERE id = $1
            "#,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn delete_user(&self, user_id: i32) -> Result<(), AuthError> {
        let result = sqlx::query!(
            r#"
            DELETE FROM users
            WHERE id = $1
            "#,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AuthError::UserNotFound);
        }

        Ok(())
    }
}

struct UserRow {
    id: i32,
    email: String,
    name: String,
    hashed_password: String,
    email_verified_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<UserRow> for User {
    fn from(row: UserRow) -> Self {
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
