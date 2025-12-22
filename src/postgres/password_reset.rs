use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};

use crate::crypto::hash_token;
use crate::{AuthError, PasswordResetRepository, PasswordResetToken};

#[derive(Clone)]
pub struct PostgresPasswordResetRepository {
    pool: PgPool,
}

impl PostgresPasswordResetRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn generate_token() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..32)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect()
    }
}

#[derive(FromRow)]
struct ResetTokenRecord {
    token_hash: String,
    user_id: i32,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

#[async_trait]
impl PasswordResetRepository for PostgresPasswordResetRepository {
    async fn create_reset_token(
        &self,
        user_id: i32,
        expires_at: DateTime<Utc>,
    ) -> Result<PasswordResetToken, AuthError> {
        let plain_token = Self::generate_token();
        let token_hash = hash_token(&plain_token);

        let row: ResetTokenRecord = sqlx::query_as(
            "INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3) RETURNING token_hash, user_id, expires_at, created_at"
        )
        .bind(&token_hash)
        .bind(user_id)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(PasswordResetToken {
            token: plain_token,
            user_id: row.user_id,
            expires_at: row.expires_at,
            created_at: row.created_at,
        })
    }

    async fn find_reset_token(&self, token: &str) -> Result<Option<PasswordResetToken>, AuthError> {
        let token_hash = hash_token(token);

        let row: Option<ResetTokenRecord> = sqlx::query_as(
            "SELECT token_hash, user_id, expires_at, created_at FROM password_reset_tokens WHERE token_hash = $1"
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(row.map(|r| PasswordResetToken {
            token: r.token_hash,
            user_id: r.user_id,
            expires_at: r.expires_at,
            created_at: r.created_at,
        }))
    }

    async fn delete_reset_token(&self, token: &str) -> Result<(), AuthError> {
        let token_hash = hash_token(token);

        sqlx::query("DELETE FROM password_reset_tokens WHERE token_hash = $1")
            .bind(&token_hash)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(())
    }
}
