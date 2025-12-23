// these tests use #[serial] to run sequentially because setup_db() truncates
// all tables before each test. without serial, parallel tests would interfere
// with each other's data.
#![allow(clippy::indexing_slicing)]

//! End-to-end tests for `PostgreSQL` repositories.
//!
//! These tests require a running `PostgreSQL` database.
//! Run with: `cargo test --features sqlx_postgres --test e2e_postgres`
//!
//! Before running, start the database:
//! ```sh
//! docker-compose up -d
//! ```

#![cfg(feature = "sqlx_postgres")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chrono::{Duration, Utc};
use enclave::actions::{LoginAction, SignupAction};
#[cfg(feature = "_audit_log")]
use enclave::postgres::PostgresAuditLogRepository;
use enclave::postgres::{
    PostgresEmailVerificationRepository, PostgresPasswordResetRepository,
    PostgresRateLimiterRepository, PostgresTokenRepository, PostgresUserRepository,
};
#[cfg(feature = "_audit_log")]
use enclave::{AuditEventType, AuditLogRepository};
#[cfg(feature = "rate_limit")]
use enclave::rate_limit::{Limit, PostgresRateLimitStore, RateLimitStore, RateLimiter};
use enclave::{
    EmailVerificationRepository, PasswordResetRepository, RateLimiterRepository, TokenRepository,
    UserRepository,
};
use serial_test::serial;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
#[cfg(feature = "rate_limit")]
use std::sync::Arc;

async fn setup_db() -> PgPool {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://enclave:enclave@localhost:5432/enclave_test".to_owned());

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to connect to database");

    // Run migrations
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    // Clean up tables before each test
    sqlx::query("TRUNCATE users, access_tokens, password_reset_tokens, email_verification_tokens, login_attempts, audit_logs, rate_limits CASCADE")
        .execute(&pool)
        .await
        .expect("Failed to truncate tables");

    pool
}

#[tokio::test]
#[serial]
async fn test_user_repository_crud() {
    let pool = setup_db().await;
    let repo = PostgresUserRepository::new(pool);

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
    let user_repo = PostgresUserRepository::new(pool.clone());
    let token_repo = PostgresTokenRepository::new(pool);

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
        .find_token(&token.token)
        .await
        .expect("Failed to find token")
        .expect("Token not found");
    assert_eq!(found.user_id, user.id);

    // Revoke token
    token_repo
        .revoke_token(&token.token)
        .await
        .expect("Failed to revoke token");
    let revoked = token_repo
        .find_token(&token.token)
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
    let user_repo = PostgresUserRepository::new(pool.clone());
    let reset_repo = PostgresPasswordResetRepository::new(pool);

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
        .find_reset_token(&token.token)
        .await
        .expect("Failed to find token")
        .expect("Token not found");
    assert_eq!(found.user_id, user.id);

    // Delete reset token
    reset_repo
        .delete_reset_token(&token.token)
        .await
        .expect("Failed to delete token");
    let deleted = reset_repo
        .find_reset_token(&token.token)
        .await
        .expect("Failed to query");
    assert!(deleted.is_none());
}

#[tokio::test]
#[serial]
async fn test_email_verification_repository() {
    let pool = setup_db().await;
    let user_repo = PostgresUserRepository::new(pool.clone());
    let verification_repo = PostgresEmailVerificationRepository::new(pool);

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
        .find_verification_token(&token.token)
        .await
        .expect("Failed to find token")
        .expect("Token not found");
    assert_eq!(found.user_id, user.id);

    // Delete verification token
    verification_repo
        .delete_verification_token(&token.token)
        .await
        .expect("Failed to delete token");
    let deleted = verification_repo
        .find_verification_token(&token.token)
        .await
        .expect("Failed to query");
    assert!(deleted.is_none());
}

#[tokio::test]
#[serial]
async fn test_rate_limiter_repository() {
    let pool = setup_db().await;
    let rate_repo = PostgresRateLimiterRepository::new(pool);

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
#[cfg(feature = "_audit_log")]
async fn test_audit_log_repository() {
    let pool = setup_db().await;
    let user_repo = PostgresUserRepository::new(pool.clone());
    let audit_repo = PostgresAuditLogRepository::new(pool);

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
    let user_repo = PostgresUserRepository::new(pool.clone());
    let token_repo = PostgresTokenRepository::new(pool.clone());
    let rate_repo = PostgresRateLimiterRepository::new(pool);

    // Signup
    let signup = SignupAction::new(user_repo.clone());
    let user = signup
        .execute("flow@example.com", "securepassword123")
        .await
        .expect("Failed to signup");
    assert_eq!(user.email, "flow@example.com");

    // Login
    let login = LoginAction::new(user_repo, token_repo, rate_repo);
    let (logged_in_user, token) = login
        .execute("flow@example.com", "securepassword123")
        .await
        .expect("Failed to login");
    assert_eq!(logged_in_user.id, user.id);
    assert!(!token.token.is_empty());
}

// Rate Limit Store E2E Tests

#[tokio::test]
#[serial]
#[cfg(feature = "rate_limit")]
async fn test_postgres_rate_limit_store_increment() {
    let pool = setup_db().await;
    let store = PostgresRateLimitStore::new(pool);

    // First increment creates entry
    let info = store
        .increment("test-key", 60)
        .await
        .expect("Failed to increment");
    assert_eq!(info.attempts, 1);
    assert!(info.reset_at > Utc::now());

    // Subsequent increments increase counter
    let info = store
        .increment("test-key", 60)
        .await
        .expect("Failed to increment");
    assert_eq!(info.attempts, 2);

    let info = store
        .increment("test-key", 60)
        .await
        .expect("Failed to increment");
    assert_eq!(info.attempts, 3);
}

#[tokio::test]
#[serial]
#[cfg(feature = "rate_limit")]
async fn test_postgres_rate_limit_store_get() {
    let pool = setup_db().await;
    let store = PostgresRateLimitStore::new(pool);

    // Non-existent key returns None
    let info = store.get("nonexistent").await.expect("Failed to get");
    assert!(info.is_none());

    // After increment, key exists
    store
        .increment("test-key", 60)
        .await
        .expect("Failed to increment");
    let info = store.get("test-key").await.expect("Failed to get");
    assert!(info.is_some());
    assert_eq!(info.unwrap().attempts, 1);
}

#[tokio::test]
#[serial]
#[cfg(feature = "rate_limit")]
async fn test_postgres_rate_limit_store_reset() {
    let pool = setup_db().await;
    let store = PostgresRateLimitStore::new(pool);

    // Create some entries
    store
        .increment("test-key", 60)
        .await
        .expect("Failed to increment");
    store
        .increment("test-key", 60)
        .await
        .expect("Failed to increment");

    let info = store.get("test-key").await.expect("Failed to get");
    assert_eq!(info.unwrap().attempts, 2);

    // Reset clears the entry
    store.reset("test-key").await.expect("Failed to reset");

    let info = store.get("test-key").await.expect("Failed to get");
    assert!(info.is_none());
}

#[tokio::test]
#[serial]
#[cfg(feature = "rate_limit")]
async fn test_postgres_rate_limit_store_remaining() {
    let pool = setup_db().await;
    let store = PostgresRateLimitStore::new(pool);

    // Full capacity when no entries
    let remaining = store
        .remaining("test-key", 5)
        .await
        .expect("Failed to get remaining");
    assert_eq!(remaining, 5);

    // Decreases after increments
    store
        .increment("test-key", 60)
        .await
        .expect("Failed to increment");
    store
        .increment("test-key", 60)
        .await
        .expect("Failed to increment");

    let remaining = store
        .remaining("test-key", 5)
        .await
        .expect("Failed to get remaining");
    assert_eq!(remaining, 3);
}

#[tokio::test]
#[serial]
#[cfg(feature = "rate_limit")]
async fn test_postgres_rate_limit_store_different_keys() {
    let pool = setup_db().await;
    let store = PostgresRateLimitStore::new(pool);

    // Different keys have separate counters
    store
        .increment("key-1", 60)
        .await
        .expect("Failed to increment");
    store
        .increment("key-1", 60)
        .await
        .expect("Failed to increment");
    store
        .increment("key-2", 60)
        .await
        .expect("Failed to increment");

    let info1 = store.get("key-1").await.expect("Failed to get").unwrap();
    let info2 = store.get("key-2").await.expect("Failed to get").unwrap();

    assert_eq!(info1.attempts, 2);
    assert_eq!(info2.attempts, 1);
}

// RateLimiter E2E Tests (with PostgreSQL store)

#[tokio::test]
#[serial]
#[cfg(feature = "rate_limit")]
async fn test_rate_limiter_with_postgres_store() {
    let pool = setup_db().await;
    let store: Arc<dyn RateLimitStore> = Arc::new(PostgresRateLimitStore::new(pool));

    let limiter = RateLimiter::new(store)
        .for_("api", Limit::per_minute(3))
        .for_("login", Limit::per_minute(2));

    // First 3 API requests should be allowed
    for i in 0..3 {
        let result = limiter.hit("api", "user-1").await.expect("Failed to hit");
        assert!(result.is_allowed(), "Request {} should be allowed", i + 1);
    }

    // 4th should be rate limited
    let result = limiter.hit("api", "user-1").await.expect("Failed to hit");
    assert!(result.is_limited());

    // Different limiter name has its own quota
    let result = limiter.hit("login", "user-1").await.expect("Failed to hit");
    assert!(result.is_allowed());
}

#[tokio::test]
#[serial]
#[cfg(feature = "rate_limit")]
async fn test_rate_limiter_different_users() {
    let pool = setup_db().await;
    let store: Arc<dyn RateLimitStore> = Arc::new(PostgresRateLimitStore::new(pool));

    let limiter = RateLimiter::new(store).for_("api", Limit::per_minute(2));

    // User 1 exhausts quota
    limiter.hit("api", "user-1").await.expect("Failed to hit");
    limiter.hit("api", "user-1").await.expect("Failed to hit");
    let result = limiter.hit("api", "user-1").await.expect("Failed to hit");
    assert!(result.is_limited());

    // User 2 still has full quota
    let result = limiter.hit("api", "user-2").await.expect("Failed to hit");
    assert!(result.is_allowed());
}

#[tokio::test]
#[serial]
#[cfg(feature = "rate_limit")]
async fn test_rate_limiter_clear() {
    let pool = setup_db().await;
    let store: Arc<dyn RateLimitStore> = Arc::new(PostgresRateLimitStore::new(pool));

    let limiter = RateLimiter::new(store).for_("api", Limit::per_minute(2));

    // Exhaust quota
    limiter.hit("api", "user-1").await.expect("Failed to hit");
    limiter.hit("api", "user-1").await.expect("Failed to hit");
    let result = limiter.hit("api", "user-1").await.expect("Failed to hit");
    assert!(result.is_limited());

    // Clear and retry
    limiter
        .clear("api", "user-1")
        .await
        .expect("Failed to clear");

    let result = limiter.hit("api", "user-1").await.expect("Failed to hit");
    assert!(result.is_allowed());
}

#[tokio::test]
#[serial]
#[cfg(feature = "rate_limit")]
async fn test_rate_limiter_remaining() {
    let pool = setup_db().await;
    let store: Arc<dyn RateLimitStore> = Arc::new(PostgresRateLimitStore::new(pool));

    let limiter = RateLimiter::new(store).for_("api", Limit::per_minute(5));

    // Full capacity initially
    let remaining = limiter
        .remaining("api", "user-1")
        .await
        .expect("Failed to get remaining");
    assert_eq!(remaining, 5);

    // Decreases after hits
    limiter.hit("api", "user-1").await.expect("Failed to hit");
    limiter.hit("api", "user-1").await.expect("Failed to hit");

    let remaining = limiter
        .remaining("api", "user-1")
        .await
        .expect("Failed to get remaining");
    assert_eq!(remaining, 3);
}

#[tokio::test]
#[serial]
#[cfg(feature = "rate_limit")]
async fn test_rate_limiter_too_many_attempts() {
    let pool = setup_db().await;
    let store: Arc<dyn RateLimitStore> = Arc::new(PostgresRateLimitStore::new(pool));

    let limiter = RateLimiter::new(store).for_("api", Limit::per_minute(2));

    // Not too many yet
    assert!(
        !limiter
            .too_many_attempts("api", "user-1")
            .await
            .expect("Failed to check")
    );

    // After exhausting quota
    limiter.hit("api", "user-1").await.expect("Failed to hit");
    limiter.hit("api", "user-1").await.expect("Failed to hit");

    assert!(
        limiter
            .too_many_attempts("api", "user-1")
            .await
            .expect("Failed to check")
    );
}

#[tokio::test]
#[serial]
#[cfg(feature = "rate_limit")]
async fn test_rate_limiter_attempt_closure() {
    let pool = setup_db().await;
    let store: Arc<dyn RateLimitStore> = Arc::new(PostgresRateLimitStore::new(pool));

    let limiter = RateLimiter::new(store).for_("api", Limit::per_minute(2));

    // First attempt executes closure
    let result = limiter
        .attempt("api", "user-1", || async { 42 })
        .await
        .expect("Failed to attempt");
    assert_eq!(result.unwrap(), 42);

    // Second attempt executes closure
    let result = limiter
        .attempt("api", "user-1", || async { 43 })
        .await
        .expect("Failed to attempt");
    assert_eq!(result.unwrap(), 43);

    // Third attempt is rate limited (closure not executed)
    let result = limiter
        .attempt("api", "user-1", || async { 44 })
        .await
        .expect("Failed to attempt");
    assert!(result.is_err());
}
