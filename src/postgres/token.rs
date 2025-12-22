use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};

use crate::crypto::hash_token;
use crate::repository::CreateTokenOptions;
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
    name: Option<String>,
    abilities: serde_json::Value,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
}

impl TokenRecord {
    fn into_access_token(self, plain_token: String) -> AccessToken {
        let abilities: Vec<String> = serde_json::from_value(self.abilities)
            .unwrap_or_else(|_| vec!["*".to_owned()]);

        AccessToken {
            token: plain_token,
            user_id: self.user_id,
            name: self.name,
            abilities,
            expires_at: self.expires_at,
            created_at: self.created_at,
            last_used_at: self.last_used_at,
        }
    }
}

#[async_trait]
impl TokenRepository for PostgresTokenRepository {
    async fn create_token(
        &self,
        user_id: i32,
        expires_at: DateTime<Utc>,
    ) -> Result<AccessToken, AuthError> {
        self.create_token_with_options(user_id, expires_at, CreateTokenOptions::default())
            .await
    }

    async fn create_token_with_options(
        &self,
        user_id: i32,
        expires_at: DateTime<Utc>,
        options: CreateTokenOptions,
    ) -> Result<AccessToken, AuthError> {
        let plain_token = Self::generate_token();
        let token_hash = hash_token(&plain_token);

        let abilities = if options.abilities.is_empty() {
            vec!["*".to_owned()]
        } else {
            options.abilities
        };
        let abilities_json = serde_json::to_value(&abilities)
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let row: TokenRecord = sqlx::query_as(
            r#"INSERT INTO access_tokens (token_hash, user_id, name, abilities, expires_at)
               VALUES ($1, $2, $3, $4, $5)
               RETURNING token_hash, user_id, name, abilities, expires_at, created_at, last_used_at"#
        )
        .bind(&token_hash)
        .bind(user_id)
        .bind(&options.name)
        .bind(&abilities_json)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(row.into_access_token(plain_token))
    }

    async fn find_token(&self, token: &str) -> Result<Option<AccessToken>, AuthError> {
        let token_hash = hash_token(token);

        let row: Option<TokenRecord> = sqlx::query_as(
            r#"SELECT token_hash, user_id, name, abilities, expires_at, created_at, last_used_at
               FROM access_tokens WHERE token_hash = $1"#
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(row.map(|r| r.into_access_token(token_hash)))
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

    async fn touch_token(&self, token: &str) -> Result<(), AuthError> {
        let token_hash = hash_token(token);

        sqlx::query("UPDATE access_tokens SET last_used_at = NOW() WHERE token_hash = $1")
            .bind(&token_hash)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn prune_expired(&self) -> Result<u64, AuthError> {
        let result = sqlx::query("DELETE FROM access_tokens WHERE expires_at < NOW()")
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(result.rows_affected())
    }
}
