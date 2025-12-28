// these tests use #[serial] to run sequentially because setup_db() recreates
// the database each time. without serial, parallel tests would interfere
// with each other's data.
#![allow(clippy::indexing_slicing)]

//! End-to-end tests for `SQLite` repositories.
//!
//! These tests use an in-memory `SQLite` database.
//! Run with: `cargo test --features sqlx_sqlite --test e2e_sqlite`

#![cfg(feature = "sqlx_sqlite")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chrono::{Duration, Utc};
use enclave::actions::{LoginAction, SignupAction};
#[cfg(feature = "audit_log")]
use enclave::sqlite::SqliteAuditLogRepository;
use enclave::sqlite::{
    SqliteEmailVerificationRepository, SqlitePasswordResetRepository, SqliteRateLimiterRepository,
    SqliteTokenRepository, SqliteUserRepository, migrations,
};
#[cfg(feature = "audit_log")]
use enclave::{AuditEventType, AuditLogRepository};
use enclave::{
    EmailVerificationRepository, PasswordResetRepository, RateLimiterRepository, SecretString,
    StatefulTokenRepository, TokenRepository, UserRepository,
};
use serial_test::serial;
use sqlx::SqlitePool;
use sqlx::sqlite::SqlitePoolOptions;

async fn setup_db() -> SqlitePool {
    // Use in-memory database for testing
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("Failed to connect to in-memory SQLite database");

    // Run migrations
    migrations::run(&pool)
        .await
        .expect("Failed to run migrations");

    pool
}

#[tokio::test]
#[serial]
async fn test_user_repository_crud() {
    let pool = setup_db().await;
    let repo = SqliteUserRepository::new(pool);

    // Create user
    let user = repo
        .create_user("test@example.com", "hashedpassword123")
        .await
        .expect("Failed to create user");
    assert_eq!(user.email, "test@example.com");
    assert!(user.id > 0);

    // Find by email
    let found = repo
        .find_user_by_email("test@example.com")
        .await
        .expect("Failed to find user")
        .expect("User not found");
    assert_eq!(found.id, user.id);

    // Find by id
    let found = repo
        .find_user_by_id(user.id)
        .await
        .expect("Failed to find user")
        .expect("User not found");
    assert_eq!(found.email, "test@example.com");

    // Update user
    let updated = repo
        .update_user(user.id, "New Name", "newemail@example.com")
        .await
        .expect("Failed to update user");
    assert_eq!(updated.name, "New Name");
    assert_eq!(updated.email, "newemail@example.com");

    // Verify email
    repo.verify_email(user.id)
        .await
        .expect("Failed to verify email");
    let verified = repo
        .find_user_by_id(user.id)
        .await
        .expect("Failed to find user")
        .expect("User not found");
    assert!(verified.email_verified_at.is_some());

    // Update password
    repo.update_password(user.id, "newhashedpassword")
        .await
        .expect("Failed to update password");
    let updated = repo
        .find_user_by_id(user.id)
        .await
        .expect("Failed to find user")
        .expect("User not found");
    assert_eq!(updated.hashed_password, "newhashedpassword");

    // Delete user
    repo.delete_user(user.id)
        .await
        .expect("Failed to delete user");
    let deleted = repo
        .find_user_by_id(user.id)
        .await
        .expect("Failed to query");
    assert!(deleted.is_none());
}

#[tokio::test]
#[serial]
async fn test_token_repository() {
    let pool = setup_db().await;
    let user_repo = SqliteUserRepository::new(pool.clone());
    let token_repo = SqliteTokenRepository::new(pool);

    // Create a user first
    let user = user_repo
        .create_user("token@example.com", "password")
        .await
        .expect("Failed to create user");

    // Create token
    let expires_at = Utc::now() + Duration::hours(1);
    let token = token_repo
        .create_token(user.id, expires_at)
        .await
        .expect("Failed to create token");
    assert_eq!(token.user_id, user.id);
    assert!(!token.token.is_empty());

    // Find token (using plain token)
    let found = token_repo
        .find_token(token.token.expose_secret())
        .await
        .expect("Failed to find token")
        .expect("Token not found");
    assert_eq!(found.user_id, user.id);

    // Revoke token
    token_repo
        .revoke_token(token.token.expose_secret())
        .await
        .expect("Failed to revoke token");
    let revoked = token_repo
        .find_token(token.token.expose_secret())
        .await
        .expect("Failed to query");
    assert!(revoked.is_none());

    // Create multiple tokens and revoke all
    let _t1 = token_repo
        .create_token(user.id, expires_at)
        .await
        .expect("Failed to create token");
    let _t2 = token_repo
        .create_token(user.id, expires_at)
        .await
        .expect("Failed to create token");
    token_repo
        .revoke_all_user_tokens(user.id)
        .await
        .expect("Failed to revoke all tokens");
}

#[tokio::test]
#[serial]
async fn test_password_reset_repository() {
    let pool = setup_db().await;
    let user_repo = SqliteUserRepository::new(pool.clone());
    let reset_repo = SqlitePasswordResetRepository::new(pool);

    let user = user_repo
        .create_user("reset@example.com", "password")
        .await
        .expect("Failed to create user");

    // Create reset token
    let expires_at = Utc::now() + Duration::hours(1);
    let token = reset_repo
        .create_reset_token(user.id, expires_at)
        .await
        .expect("Failed to create reset token");
    assert_eq!(token.user_id, user.id);

    // Find reset token
    let found = reset_repo
        .find_reset_token(token.token.expose_secret())
        .await
        .expect("Failed to find token")
        .expect("Token not found");
    assert_eq!(found.user_id, user.id);

    // Delete reset token
    reset_repo
        .delete_reset_token(token.token.expose_secret())
        .await
        .expect("Failed to delete token");
    let deleted = reset_repo
        .find_reset_token(token.token.expose_secret())
        .await
        .expect("Failed to query");
    assert!(deleted.is_none());
}

#[tokio::test]
#[serial]
async fn test_email_verification_repository() {
    let pool = setup_db().await;
    let user_repo = SqliteUserRepository::new(pool.clone());
    let verification_repo = SqliteEmailVerificationRepository::new(pool);

    let user = user_repo
        .create_user("verify@example.com", "password")
        .await
        .expect("Failed to create user");

    // Create verification token
    let expires_at = Utc::now() + Duration::hours(24);
    let token = verification_repo
        .create_verification_token(user.id, expires_at)
        .await
        .expect("Failed to create verification token");
    assert_eq!(token.user_id, user.id);

    // Find verification token
    let found = verification_repo
        .find_verification_token(token.token.expose_secret())
        .await
        .expect("Failed to find token")
        .expect("Token not found");
    assert_eq!(found.user_id, user.id);

    // Delete verification token
    verification_repo
        .delete_verification_token(token.token.expose_secret())
        .await
        .expect("Failed to delete token");
    let deleted = verification_repo
        .find_verification_token(token.token.expose_secret())
        .await
        .expect("Failed to query");
    assert!(deleted.is_none());
}

#[tokio::test]
#[serial]
async fn test_rate_limiter_repository() {
    let pool = setup_db().await;
    let rate_repo = SqliteRateLimiterRepository::new(pool);

    let email = "ratelimit@example.com";
    let since = Utc::now() - Duration::minutes(15);

    // Record failed attempts
    rate_repo
        .record_attempt(email, false, Some("127.0.0.1"))
        .await
        .expect("Failed to record attempt");
    rate_repo
        .record_attempt(email, false, Some("127.0.0.1"))
        .await
        .expect("Failed to record attempt");
    rate_repo
        .record_attempt(email, true, Some("127.0.0.1"))
        .await
        .expect("Failed to record attempt");

    // Get failed attempts (should be 2)
    let count = rate_repo
        .get_recent_failed_attempts(email, since)
        .await
        .expect("Failed to get attempts");
    assert_eq!(count, 2);

    // Clear attempts
    rate_repo
        .clear_attempts(email)
        .await
        .expect("Failed to clear attempts");
    let count = rate_repo
        .get_recent_failed_attempts(email, since)
        .await
        .expect("Failed to get attempts");
    assert_eq!(count, 0);
}

#[tokio::test]
#[serial]
#[cfg(feature = "audit_log")]
async fn test_audit_log_repository() {
    let pool = setup_db().await;
    let user_repo = SqliteUserRepository::new(pool.clone());
    let audit_repo = SqliteAuditLogRepository::new(pool);

    let user = user_repo
        .create_user("audit@example.com", "password")
        .await
        .expect("Failed to create user");

    // Log events
    let log1 = audit_repo
        .log_event(
            Some(user.id),
            AuditEventType::Signup,
            Some("127.0.0.1"),
            Some("Mozilla/5.0"),
            None,
        )
        .await
        .expect("Failed to log event");
    assert_eq!(log1.event_type, AuditEventType::Signup);

    let _log2 = audit_repo
        .log_event(
            Some(user.id),
            AuditEventType::LoginSuccess,
            Some("127.0.0.1"),
            None,
            Some(r#"{"browser": "chrome"}"#),
        )
        .await
        .expect("Failed to log event");

    // Get user events
    let events = audit_repo
        .get_user_events(user.id, 10)
        .await
        .expect("Failed to get events");
    assert_eq!(events.len(), 2);
    // Events should be in reverse chronological order
    assert_eq!(events[0].event_type, AuditEventType::LoginSuccess);
    assert_eq!(events[1].event_type, AuditEventType::Signup);
}

#[tokio::test]
#[serial]
async fn test_signup_and_login_flow() {
    let pool = setup_db().await;
    let user_repo = SqliteUserRepository::new(pool.clone());
    let token_repo = SqliteTokenRepository::new(pool.clone());
    let rate_repo = SqliteRateLimiterRepository::new(pool);

    // Signup
    let signup = SignupAction::new(user_repo.clone());
    let password = SecretString::new("securepassword123");
    let user = signup
        .execute("flow@example.com", &password)
        .await
        .expect("Failed to signup");
    assert_eq!(user.email, "flow@example.com");

    // Login
    let login = LoginAction::new(user_repo, token_repo, rate_repo);
    let (logged_in_user, token) = login
        .execute("flow@example.com", &password)
        .await
        .expect("Failed to login");
    assert_eq!(logged_in_user.id, user.id);
    assert!(!token.token.is_empty());
}
