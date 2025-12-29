use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};

use crate::{AuditEventType, AuditLog, AuditLogRepository, AuthError};

#[derive(Clone)]
pub struct PostgresAuditLogRepository {
    pool: PgPool,
}

impl PostgresAuditLogRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn event_type_to_string(event_type: &AuditEventType) -> &'static str {
    match event_type {
        AuditEventType::Signup => "signup",
        AuditEventType::LoginSuccess => "login_success",
        AuditEventType::LoginFailed => "login_failed",
        AuditEventType::Logout => "logout",
        AuditEventType::PasswordChanged => "password_changed",
        AuditEventType::PasswordResetRequested => "password_reset_requested",
        AuditEventType::PasswordReset => "password_reset",
        AuditEventType::EmailVerificationSent => "email_verification_sent",
        AuditEventType::EmailVerified => "email_verified",
        AuditEventType::TokenRefreshed => "token_refreshed",
        AuditEventType::AccountDeleted => "account_deleted",
    }
}

fn string_to_event_type(s: &str) -> AuditEventType {
    match s {
        "signup" => AuditEventType::Signup,
        "login_success" => AuditEventType::LoginSuccess,
        "logout" => AuditEventType::Logout,
        "password_changed" => AuditEventType::PasswordChanged,
        "password_reset_requested" => AuditEventType::PasswordResetRequested,
        "password_reset" => AuditEventType::PasswordReset,
        "email_verification_sent" => AuditEventType::EmailVerificationSent,
        "email_verified" => AuditEventType::EmailVerified,
        "token_refreshed" => AuditEventType::TokenRefreshed,
        "account_deleted" => AuditEventType::AccountDeleted,
        _ => AuditEventType::LoginFailed,
    }
}

#[derive(FromRow)]
struct AuditLogRecord {
    id: i64,
    user_id: Option<i32>,
    event_type: String,
    ip_address: Option<String>,
    user_agent: Option<String>,
    metadata: Option<serde_json::Value>,
    created_at: DateTime<Utc>,
}

#[async_trait]
impl AuditLogRepository for PostgresAuditLogRepository {
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(skip(self, ip_address, user_agent, metadata), err)
    )]
    async fn log_event(
        &self,
        user_id: Option<i32>,
        event_type: AuditEventType,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        metadata: Option<&str>,
    ) -> Result<AuditLog, AuthError> {
        let event_type_str = event_type_to_string(&event_type);
        let metadata_json: Option<serde_json::Value> =
            metadata.and_then(|m| serde_json::from_str(m).ok());

        let row: AuditLogRecord = sqlx::query_as(
            "INSERT INTO audit_logs (user_id, event_type, ip_address, user_agent, metadata) VALUES ($1, $2, $3, $4, $5) RETURNING id, user_id, event_type, ip_address, user_agent, metadata, created_at"
        )
        .bind(user_id)
        .bind(event_type_str)
        .bind(ip_address)
        .bind(user_agent)
        .bind(metadata_json)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"log_event\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(AuditLog {
            id: row.id,
            user_id: row.user_id,
            event_type: string_to_event_type(&row.event_type),
            ip_address: row.ip_address,
            user_agent: row.user_agent,
            metadata: row.metadata.map(|v| v.to_string()),
            created_at: row.created_at,
        })
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), err))]
    async fn get_user_events(
        &self,
        user_id: i32,
        limit: usize,
    ) -> Result<Vec<AuditLog>, AuthError> {
        let rows: Vec<AuditLogRecord> = sqlx::query_as(
            "SELECT id, user_id, event_type, ip_address, user_agent, metadata, created_at FROM audit_logs WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2"
        )
        .bind(user_id)
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            log::error!(target: "enclave_auth", "msg=\"database error\", operation=\"get_user_events\", error=\"{e}\"");
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(rows
            .into_iter()
            .map(|r| AuditLog {
                id: r.id,
                user_id: r.user_id,
                event_type: string_to_event_type(&r.event_type),
                ip_address: r.ip_address,
                user_agent: r.user_agent,
                metadata: r.metadata.map(|v| v.to_string()),
                created_at: r.created_at,
            })
            .collect())
    }
}
