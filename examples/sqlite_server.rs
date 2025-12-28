#![allow(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::str_to_string,
    clippy::missing_docs_in_private_items,
    clippy::doc_markdown
)]

//! SQLite Authentication Server Example
//!
//! A complete example showing how to set up an auth server with SQLite.
//! Uses opaque tokens stored in the database (revocable).
//!
//! Run with: `cargo run --example sqlite_server --features "actix sqlx_sqlite"`
//!
//! Environment variables:
//!   DATABASE_URL=sqlite:./enclave.db (optional, defaults to in-memory)
//!
//! Test endpoints:
//!   curl -X POST http://localhost:8080/auth/register \
//!     -H "Content-Type: application/json" \
//!     -d '{"email": "user@example.com", "password": "securepassword"}'

use actix_web::{App, HttpServer, web};
use enclave::api::actix::auth_routes;
use enclave::sqlite::{
    SqliteEmailVerificationRepository, SqlitePasswordResetRepository, SqliteRateLimiterRepository,
    SqliteTokenRepository, SqliteUserRepository, create_repositories, migrations,
};
use sqlx::sqlite::SqlitePoolOptions;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
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

    println!("Starting SQLite auth server on http://localhost:8080");
    println!("Database: {database_url}");
    println!("Endpoints:");
    println!("  POST /auth/register       - Create account");
    println!("  POST /auth/login          - Login (returns opaque token)");
    println!("  GET  /auth/me             - Get current user");
    println!("  POST /auth/logout         - Logout (revokes token)");
    println!("  POST /auth/forgot-password- Request password reset");
    println!("  POST /auth/reset-password - Reset password with token");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(user_repo.clone()))
            .app_data(web::Data::new(token_repo.clone()))
            .app_data(web::Data::new(rate_limiter.clone()))
            .app_data(web::Data::new(password_reset.clone()))
            .app_data(web::Data::new(email_verification.clone()))
            .configure(
                auth_routes::<
                    SqliteUserRepository,
                    SqliteTokenRepository,
                    SqliteRateLimiterRepository,
                    SqlitePasswordResetRepository,
                    SqliteEmailVerificationRepository,
                >,
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
