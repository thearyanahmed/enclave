#![allow(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::str_to_string,
    clippy::missing_docs_in_private_items,
    clippy::doc_markdown
)]

//! Axum PostgreSQL Authentication Server Example
//!
//! A complete example showing how to set up an auth server with PostgreSQL using Axum.
//! Uses opaque tokens stored in the database (revocable).
//!
//! Prerequisites:
//!   - PostgreSQL running (use docker-compose up -d)
//!   - Run migrations: sqlx migrate run
//!
//! Run with: `cargo run --example axum_postgres_server --features "axum_api sqlx_postgres"`
//!
//! Environment variables:
//!   DATABASE_URL=postgres://user:password@localhost:5432/enclave
//!
//! Test endpoints:
//!   curl -X POST http://localhost:8080/auth/register \
//!     -H "Content-Type: application/json" \
//!     -d '{"email": "user@example.com", "password": "securepassword"}'

use axum::Router;
use enclave::api::axum::{auth_routes, AppState};
use enclave::postgres::{
    PostgresEmailVerificationRepository, PostgresPasswordResetRepository,
    PostgresRateLimiterRepository, PostgresTokenRepository, PostgresUserRepository,
    create_repositories,
};
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    // Load database URL from environment
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    // Create connection pool
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to create pool");

    // Run migrations
    sqlx::migrate!("./migrations")
        .run(&pool)
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
                PostgresUserRepository,
                PostgresTokenRepository,
                PostgresRateLimiterRepository,
                PostgresPasswordResetRepository,
                PostgresEmailVerificationRepository,
            >(),
        )
        .with_state(state);

    println!("Starting Axum PostgreSQL auth server on http://localhost:8080");
    println!("Connected to database");
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
