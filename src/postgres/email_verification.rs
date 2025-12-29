use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};

use crate::crypto::{generate_token_default, hash_token};
use crate::{AuthError, EmailVerificationRepository, EmailVerificationToken, SecretString};

#[derive(Clone)]
pub struct PostgresEmailVerificationRepository {
    pool: PgPool,
}

impl PostgresEmailVerificationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(FromRow)]
struct VerificationTokenRecord {
    user_id: i64,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

#[async_trait]
impl EmailVerificationRepository for PostgresEmailVerificationRepository {
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn create_verification_token(
        &self,
        user_id: u64,
        expires_at: DateTime<Utc>,
    ) -> Result<EmailVerificationToken, AuthError> {
        let plain_token = generate_token_default();
        let token_hash = hash_token(&plain_token);

        let row: VerificationTokenRecord = sqlx::query_as(
            "INSERT INTO email_verification_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3) RETURNING token_hash, user_id, expires_at, created_at"
        )
        .bind(&token_hash)
        .bind(user_id as i64)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"create_verification_token\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(EmailVerificationToken {
            token: SecretString::new(plain_token),
            user_id: row.user_id as u64,
            expires_at: row.expires_at,
            created_at: row.created_at,
        })
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, token), err))]
    async fn find_verification_token(
        &self,
        token: &str,
    ) -> Result<Option<EmailVerificationToken>, AuthError> {
        let token_hash = hash_token(token);

        let row: Option<VerificationTokenRecord> = sqlx::query_as(
            "SELECT user_id, expires_at, created_at FROM email_verification_tokens WHERE token_hash = $1"
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"find_verification_token\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(row.map(|r| EmailVerificationToken {
            token: SecretString::new(token),
            user_id: r.user_id as u64,
            expires_at: r.expires_at,
            created_at: r.created_at,
        }))
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, token), err))]
    async fn delete_verification_token(&self, token: &str) -> Result<(), AuthError> {
        let token_hash = hash_token(token);

        sqlx::query("DELETE FROM email_verification_tokens WHERE token_hash = $1")
            .bind(&token_hash)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"delete_verification_token\", error=\"{e}\"");
                AuthError::DatabaseError(e.to_string())
            })?;

        Ok(())
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn prune_expired(&self) -> Result<u64, AuthError> {
        let result = sqlx::query("DELETE FROM email_verification_tokens WHERE expires_at < NOW()")
            .execute(&self.pool)
            .await
            .map_err(|e| {
                log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"prune_expired_verification_tokens\", error=\"{e}\"");
                AuthError::DatabaseError(e.to_string())
            })?;

        Ok(result.rows_affected())
    }
}
