#![allow(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::str_to_string,
    clippy::missing_docs_in_private_items,
    clippy::doc_markdown
)]

//! Axum SQLite Authentication Server Example
//!
//! A complete example showing how to set up an auth server with SQLite using Axum.
//! Uses opaque tokens stored in the database (revocable).
//!
//! Run with: `cargo run --example axum_sqlite_server --features "axum_api sqlx_sqlite"`
//!
//! Environment variables:
//!   DATABASE_URL=sqlite:./enclave.db (optional, defaults to in-memory)
//!
//! Test endpoints:
//!   curl -X POST http://localhost:8080/auth/register \
//!     -H "Content-Type: application/json" \
//!     -d '{"email": "user@example.com", "password": "securepassword"}'

use axum::Router;
use enclave::api::axum::{AppState, auth_routes};
use enclave::sqlite::{
    SqliteEmailVerificationRepository, SqlitePasswordResetRepository,
    SqliteRateLimiterRepository, SqliteTokenRepository, SqliteUserRepository,
    create_repositories, migrations,
};
use sqlx::sqlite::SqlitePoolOptions;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    // Load database URL from environment, default to in-memory
    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite::memory:".to_string());

    // Create connection pool
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to create pool");

    // Run migrations
    migrations::run(&pool)
        .await
        .expect("Failed to run migrations");

    // Create repositories using the helper function
    let (user_repo, token_repo, password_reset, email_verification, rate_limiter) =
        create_repositories(pool);

    // Create application state
    let state = AppState {
        user_repo,
        token_repo,
        rate_limiter,
        password_reset,
        email_verification,
    };

    // Build the router
    let app = Router::new()
        .nest(
            "/auth",
            auth_routes::<
                SqliteUserRepository,
                SqliteTokenRepository,
                SqliteRateLimiterRepository,
                SqlitePasswordResetRepository,
                SqliteEmailVerificationRepository,
            >(),
        )
        .with_state(state);

    println!("Starting Axum SQLite auth server on http://localhost:8080");
    println!("Database: {database_url}");
    println!("Endpoints:");
    println!("  POST /auth/register       - Create account");
    println!("  POST /auth/login          - Login (returns opaque token)");
    println!("  GET  /auth/me             - Get current user");
    println!("  POST /auth/logout         - Logout (revokes token)");
    println!("  POST /auth/forgot-password- Request password reset");
    println!("  POST /auth/reset-password - Reset password with token");

    let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
