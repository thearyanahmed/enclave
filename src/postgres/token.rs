use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};

use crate::crypto::hash_token;
use crate::{AccessToken, AuthError, TokenRepository};

#[derive(Clone)]
pub struct PostgresTokenRepository {
    pool: PgPool,
}

impl PostgresTokenRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn generate_token() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..32)
            .map(|_| char::from(rng.sample(rand::distributions::Alphanumeric)))
            .collect()
    }
}

#[derive(FromRow)]
struct TokenRecord {
    token_hash: String,
    user_id: i32,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

#[async_trait]
impl TokenRepository for PostgresTokenRepository {
    async fn create_token(
        &self,
        user_id: i32,
        expires_at: DateTime<Utc>,
    ) -> Result<AccessToken, AuthError> {
        let plain_token = Self::generate_token();
        let token_hash = hash_token(&plain_token);

        let row: TokenRecord = sqlx::query_as(
            "INSERT INTO access_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3) RETURNING token_hash, user_id, expires_at, created_at"
        )
        .bind(&token_hash)
        .bind(user_id)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(AccessToken {
            token: plain_token,
            user_id: row.user_id,
            expires_at: row.expires_at,
            created_at: row.created_at,
        })
    }

    async fn find_token(&self, token: &str) -> Result<Option<AccessToken>, AuthError> {
        let token_hash = hash_token(token);

        let row: Option<TokenRecord> = sqlx::query_as(
            "SELECT token_hash, user_id, expires_at, created_at FROM access_tokens WHERE token_hash = $1"
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(row.map(|r| AccessToken {
            token: r.token_hash,
            user_id: r.user_id,
            expires_at: r.expires_at,
            created_at: r.created_at,
        }))
    }

    async fn revoke_token(&self, token: &str) -> Result<(), AuthError> {
        let token_hash = hash_token(token);

        sqlx::query("DELETE FROM access_tokens WHERE token_hash = $1")
            .bind(&token_hash)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn revoke_all_user_tokens(&self, user_id: i32) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM access_tokens WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(())
    }
}
