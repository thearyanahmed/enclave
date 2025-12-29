use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, SqlitePool};

use crate::crypto::{generate_token_default, hash_token};
use crate::{AuthError, MagicLinkRepository, MagicLinkToken, SecretString};

#[derive(Clone)]
pub struct SqliteMagicLinkRepository {
    pool: SqlitePool,
}

impl SqliteMagicLinkRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[derive(FromRow)]
struct MagicLinkTokenRecord {
    user_id: i64,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

#[async_trait]
impl MagicLinkRepository for SqliteMagicLinkRepository {
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn create_magic_link_token(
        &self,
        user_id: i64,
        expires_at: DateTime<Utc>,
    ) -> Result<MagicLinkToken, AuthError> {
        let plain_token = generate_token_default();
        let token_hash = hash_token(&plain_token);

        let row: MagicLinkTokenRecord = sqlx::query_as(
            "INSERT INTO magic_link_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?) RETURNING user_id, expires_at, created_at",
        )
        .bind(&token_hash)
        .bind(user_id)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"create_magic_link_token\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(MagicLinkToken {
            token: SecretString::new(plain_token),
            user_id: row.user_id,
            expires_at: row.expires_at,
            created_at: row.created_at,
        })
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, token), err))]
    async fn find_magic_link_token(
        &self,
        token: &str,
    ) -> Result<Option<MagicLinkToken>, AuthError> {
        let token_hash = hash_token(token);

        let row: Option<MagicLinkTokenRecord> = sqlx::query_as(
            "SELECT user_id, expires_at, created_at FROM magic_link_tokens WHERE token_hash = ?",
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"find_magic_link_token\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(row.map(|r| MagicLinkToken {
            token: SecretString::new(token),
            user_id: r.user_id,
            expires_at: r.expires_at,
            created_at: r.created_at,
        }))
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, token), err))]
    async fn delete_magic_link_token(&self, token: &str) -> Result<(), AuthError> {
        let token_hash = hash_token(token);

        sqlx::query("DELETE FROM magic_link_tokens WHERE token_hash = ?")
            .bind(&token_hash)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"delete_magic_link_token\", error=\"{e}\"");
                AuthError::DatabaseError(e.to_string())
            })?;

        Ok(())
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn prune_expired(&self) -> Result<i64, AuthError> {
        let now = Utc::now();
        let result = sqlx::query("DELETE FROM magic_link_tokens WHERE expires_at < ?")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"prune_expired_magic_link_tokens\", error=\"{e}\"");
                AuthError::DatabaseError(e.to_string())
            })?;

        Ok(result.rows_affected() as i64)
    }
}
