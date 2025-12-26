#![allow(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::str_to_string,
    clippy::missing_docs_in_private_items,
    clippy::doc_markdown
)]

//! Session Authentication Server Example
//!
//! A complete example showing how to set up an auth server with cookie-based sessions.
//! Sessions are stored server-side with signed cookies for tamper protection.
//!
//! Features:
//! - HMAC-SHA256 signed cookies (tamper-proof)
//! - Sliding window session expiry
//! - Server-side session storage (in-memory for this example)
//!
//! Run with: `cargo run --example session_server --features "sessions mocks"`
//!
//! Test endpoints:
//!   curl -X POST http://localhost:8080/auth/login \
//!     -H "Content-Type: application/json" \
//!     -d '{"email": "user@example.com", "password": "securepassword"}' \
//!     -c cookies.txt
//!
//!   curl http://localhost:8080/auth/me \
//!     -b cookies.txt
//!
//!   curl -X POST http://localhost:8080/auth/logout \
//!     -b cookies.txt -c cookies.txt

use actix_web::{App, HttpServer, web};
use chrono::Duration;
use enclave::actions::SignupAction;
use enclave::api::actix::session_auth_routes;
use enclave::session::{InMemorySessionRepository, SessionConfig};
use enclave::{MockRateLimiterRepository, MockUserRepository, SecretString};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // In production, load secret from environment variable
    let session_secret = std::env::var("SESSION_SECRET")
        .unwrap_or_else(|_| "your-super-secret-key-at-least-32-bytes!".to_string());

    // Configure sessions
    let session_config = SessionConfig {
        cookie_name: "enclave_session".to_string(),
        cookie_secure: false, // Set to true in production with HTTPS
        session_lifetime: Duration::hours(2),
        secret_key: SecretString::new(session_secret),
        ..Default::default()
    };

    // In-memory session storage (use FileSessionRepository for persistence)
    let session_repo = InMemorySessionRepository::new();

    // Using mock repositories for this example
    // In production, replace with PostgresUserRepository, etc.
    let user_repo = MockUserRepository::new();
    let rate_limiter = MockRateLimiterRepository::new();

    // Pre-create a test user using SignupAction
    {
        let signup = SignupAction::new(user_repo.clone());
        let password = SecretString::new("securepassword");
        let _ = signup.execute("user@example.com", &password).await;
    }

    println!("Starting Session auth server on http://localhost:8080");
    println!();
    println!("Endpoints:");
    println!("  POST /auth/login  - Login (sets session cookie)");
    println!("  POST /auth/logout - Logout (clears session)");
    println!("  GET  /auth/me     - Get current user from session");
    println!();
    println!("Test user: user@example.com / securepassword");
    println!();
    println!("Example:");
    println!("  curl -X POST http://localhost:8080/auth/login \\");
    println!("    -H 'Content-Type: application/json' \\");
    println!("    -d '{{\"email\": \"user@example.com\", \"password\": \"securepassword\"}}' \\");
    println!("    -c cookies.txt");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(user_repo.clone()))
            .app_data(web::Data::new(session_repo.clone()))
            .app_data(web::Data::new(rate_limiter.clone()))
            .app_data(web::Data::new(session_config.clone()))
            .configure(session_auth_routes::<
                MockUserRepository,
                InMemorySessionRepository,
                MockRateLimiterRepository,
            >)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
