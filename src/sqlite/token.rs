use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, SqlitePool};

use crate::SecretString;
use crate::crypto::{generate_token_default, hash_token};
use crate::repository::CreateTokenOptions;
use crate::{AccessToken, AuthError, StatefulTokenRepository, TokenRepository};

#[derive(Clone)]
pub struct SqliteTokenRepository {
    pool: SqlitePool,
}

impl SqliteTokenRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[derive(FromRow)]
struct TokenRecord {
    user_id: i32,
    name: Option<String>,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

impl TokenRecord {
    fn into_access_token(self, plain_token: String) -> AccessToken {
        AccessToken {
            token: SecretString::new(plain_token),
            user_id: self.user_id,
            name: self.name,
            expires_at: self.expires_at,
            created_at: self.created_at,
        }
    }
}

#[async_trait]
impl TokenRepository for SqliteTokenRepository {
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn create_token(
        &self,
        user_id: i32,
        expires_at: DateTime<Utc>,
    ) -> Result<AccessToken, AuthError> {
        self.create_token_with_options(user_id, expires_at, CreateTokenOptions::default())
            .await
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, options), err))]
    async fn create_token_with_options(
        &self,
        user_id: i32,
        expires_at: DateTime<Utc>,
        options: CreateTokenOptions,
    ) -> Result<AccessToken, AuthError> {
        let plain_token = generate_token_default();
        let token_hash = hash_token(&plain_token);

        let row: TokenRecord = sqlx::query_as(
            r"INSERT INTO access_tokens (token_hash, user_id, name, expires_at)
               VALUES (?, ?, ?, ?)
               RETURNING user_id, name, expires_at, created_at",
        )
        .bind(&token_hash)
        .bind(user_id)
        .bind(&options.name)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"create_token\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(row.into_access_token(plain_token))
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, token), err))]
    async fn find_token(&self, token: &str) -> Result<Option<AccessToken>, AuthError> {
        let token_hash = hash_token(token);

        let row: Option<TokenRecord> = sqlx::query_as(
            r"SELECT user_id, name, expires_at, created_at
               FROM access_tokens WHERE token_hash = ?",
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"find_token\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(row.map(|r| r.into_access_token(token.to_owned())))
    }
}

#[async_trait]
impl StatefulTokenRepository for SqliteTokenRepository {
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, token), err))]
    async fn revoke_token(&self, token: &str) -> Result<(), AuthError> {
        let token_hash = hash_token(token);

        sqlx::query("DELETE FROM access_tokens WHERE token_hash = ?")
            .bind(&token_hash)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"revoke_token\", error=\"{e}\"");
                AuthError::DatabaseError(e.to_string())
            })?;

        Ok(())
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn revoke_all_user_tokens(&self, user_id: i32) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM access_tokens WHERE user_id = ?")
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"revoke_all_user_tokens\", error=\"{e}\"");
                AuthError::DatabaseError(e.to_string())
            })?;

        Ok(())
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn prune_expired(&self) -> Result<u64, AuthError> {
        let now = Utc::now();
        let result = sqlx::query("DELETE FROM access_tokens WHERE expires_at < ?")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"prune_expired_tokens\", error=\"{e}\"");
                AuthError::DatabaseError(e.to_string())
            })?;

        Ok(result.rows_affected())
    }
}
