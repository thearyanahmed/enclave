//! End-to-end tests for rate limiting with `PostgreSQL` store.
//!
//! These tests require a running `PostgreSQL` database and both features enabled.
//! Run with: `cargo test --features "sqlx_postgres rate_limit" --test e2e_postgres_rate_limit`
//!
//! Before running, start the database:
//! ```sh
//! docker-compose up -d
//! ```

#![cfg(all(feature = "sqlx_postgres", feature = "rate_limit"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chrono::Utc;
use enclave::postgres::migrations;
use enclave::rate_limit::{Limit, PostgresRateLimitStore, RateLimitStore, RateLimiter};
use serial_test::serial;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
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
    migrations::run_all(&pool)
        .await
        .expect("Failed to run migrations");

    // Clean up tables before each test
    sqlx::query("TRUNCATE users, access_tokens, password_reset_tokens, email_verification_tokens, login_attempts, audit_logs, rate_limits CASCADE")
        .execute(&pool)
        .await
        .expect("Failed to truncate tables");

    pool
}

// Rate Limit Store E2E Tests

#[tokio::test]
#[serial]
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

// RateLimiter E2E Tests (with `PostgreSQL` store)

#[tokio::test]
#[serial]
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
