#![allow(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::str_to_string,
    clippy::missing_docs_in_private_items,
    clippy::doc_markdown
)]

//! JWT Authentication Server Example
//!
//! A complete example showing how to set up an auth server with JWT tokens.
//! JWT tokens are stateless - no database needed for token storage.
//!
//! Features:
//! - Short-lived access tokens (15 min default)
//! - Long-lived refresh tokens (7 days default)
//! - Token rotation for security
//!
//! Run with: `cargo run --example jwt_server --features "actix jwt mocks"`
//!
//! Test endpoints:
//!   curl -X POST http://localhost:8080/auth/register \
//!     -H "Content-Type: application/json" \
//!     -d '{"email": "user@example.com", "password": "securepassword"}'
//!
//!   curl -X POST http://localhost:8080/auth/login \
//!     -H "Content-Type: application/json" \
//!     -d '{"email": "user@example.com", "password": "securepassword"}'
//!
//!   curl http://localhost:8080/auth/me \
//!     -H "Authorization: Bearer <access_token>"

use actix_web::{App, HttpServer, web};
use enclave::api::actix::stateless_auth_routes;
use enclave::jwt::{JwtConfig, JwtService, JwtTokenProvider};
use enclave::{
    MockEmailVerificationRepository, MockPasswordResetRepository, MockRateLimiterRepository,
    MockUserRepository,
};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // In production, load secret from environment variable
    let jwt_secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "your-super-secret-key-at-least-32-bytes!".to_string());

    // Configure JWT with short-lived access tokens and long-lived refresh tokens
    let jwt_config = JwtConfig::new(jwt_secret)
        .expect("JWT secret must be at least 32 bytes")
        .with_access_expiry(chrono::Duration::minutes(15))
        .with_refresh_expiry(chrono::Duration::days(7))
        .with_issuer("enclave-example");

    let jwt_service = JwtService::new(jwt_config);

    // JwtTokenProvider implements TokenRepository, so it works with existing handlers
    let jwt_provider = JwtTokenProvider::new(jwt_service.clone());

    // For direct JWT operations (token pairs, refresh), use JwtService directly:
    // let pair = jwt_service.create_token_pair(user_id)?;
    // let new_access = jwt_service.refresh_access_token(&pair.refresh_token)?;

    // Using mock repositories for this example
    // In production, replace with PostgresUserRepository, etc.
    let user_repo = MockUserRepository::new();
    let rate_limiter = MockRateLimiterRepository::new();
    let password_reset = MockPasswordResetRepository::new();
    let email_verification = MockEmailVerificationRepository::new();

    println!("Starting JWT auth server on http://localhost:8080");
    println!("Endpoints:");
    println!("  POST /auth/register - Create account");
    println!("  POST /auth/login    - Login (returns JWT)");
    println!("  GET  /auth/me       - Get current user (requires JWT)");
    println!();
    println!("Note: JWT is stateless - no logout or refresh-token endpoints.");
    println!("      Use short token expiry and client-side token deletion.");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(user_repo.clone()))
            .app_data(web::Data::new(jwt_provider.clone()))
            .app_data(web::Data::new(rate_limiter.clone()))
            .app_data(web::Data::new(password_reset.clone()))
            .app_data(web::Data::new(email_verification.clone()))
            .configure(
                stateless_auth_routes::<
                    MockUserRepository,
                    JwtTokenProvider,
                    MockRateLimiterRepository,
                    MockPasswordResetRepository,
                    MockEmailVerificationRepository,
                >,
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
