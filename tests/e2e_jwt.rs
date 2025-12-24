//! End-to-end tests for JWT authentication.
//!
//! These tests demonstrate using the same handlers with JWT tokens.
//! Run with: `cargo test --features "actix jwt mocks" --test e2e_jwt`

#![cfg(all(feature = "actix", feature = "jwt", feature = "mocks"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use actix_web::{App, http::StatusCode, test, web};

use enclave::api::actix::stateless_auth_routes;
use enclave::jwt::{JwtConfig, JwtService, JwtTokenProvider};
use enclave::{
    MockEmailVerificationRepository, MockPasswordResetRepository, MockRateLimiterRepository,
    MockUserRepository,
};

fn create_repos() -> (
    MockUserRepository,
    JwtTokenProvider,
    MockRateLimiterRepository,
    MockPasswordResetRepository,
    MockEmailVerificationRepository,
) {
    let jwt_config = JwtConfig::new("test-secret-key-for-jwt-testing!!");
    let jwt_service = JwtService::new(jwt_config);
    let jwt_provider = JwtTokenProvider::new(jwt_service);

    (
        MockUserRepository::new(),
        jwt_provider,
        MockRateLimiterRepository::new(),
        MockPasswordResetRepository::new(),
        MockEmailVerificationRepository::new(),
    )
}

macro_rules! test_app {
    ($user:expr, $token:expr, $rate:expr, $reset:expr, $verify:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($user))
                .app_data(web::Data::new($token))
                .app_data(web::Data::new($rate))
                .app_data(web::Data::new($reset))
                .app_data(web::Data::new($verify))
                .configure(
                    stateless_auth_routes::<
                        MockUserRepository,
                        JwtTokenProvider,
                        MockRateLimiterRepository,
                        MockPasswordResetRepository,
                        MockEmailVerificationRepository,
                    >,
                ),
        )
        .await
    };
}

#[actix_rt::test]
async fn test_jwt_register_and_login() {
    let (user_repo, token_repo, rate_repo, reset_repo, verification_repo) = create_repos();
    let app = test_app!(
        user_repo.clone(),
        token_repo.clone(),
        rate_repo.clone(),
        reset_repo.clone(),
        verification_repo.clone()
    );

    // Register
    let req = test::TestRequest::post()
        .uri("/auth/register")
        .set_json(serde_json::json!({
            "email": "jwt@example.com",
            "password": "securepassword123"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Login - should receive a JWT token
    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(serde_json::json!({
            "email": "jwt@example.com",
            "password": "securepassword123"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    let token = body["token"].as_str().unwrap();

    // JWT tokens have 3 parts separated by dots
    assert_eq!(
        token.split('.').count(),
        3,
        "Token should be a JWT (3 parts)"
    );
    assert_eq!(body["user"]["email"], "jwt@example.com");
}

#[actix_rt::test]
async fn test_jwt_protected_route() {
    let (user_repo, token_repo, rate_repo, reset_repo, verification_repo) = create_repos();
    let app = test_app!(
        user_repo.clone(),
        token_repo.clone(),
        rate_repo.clone(),
        reset_repo.clone(),
        verification_repo.clone()
    );

    // Register and login
    let req = test::TestRequest::post()
        .uri("/auth/register")
        .set_json(serde_json::json!({
            "email": "protected@example.com",
            "password": "securepassword123"
        }))
        .to_request();
    test::call_service(&app, req).await;

    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(serde_json::json!({
            "email": "protected@example.com",
            "password": "securepassword123"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    let token = body["token"].as_str().unwrap();

    // Access protected route with JWT
    let req = test::TestRequest::get()
        .uri("/auth/me")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["email"], "protected@example.com");
}

#[actix_rt::test]
async fn test_jwt_invalid_token_rejected() {
    let (user_repo, token_repo, rate_repo, reset_repo, verification_repo) = create_repos();
    let app = test_app!(
        user_repo,
        token_repo,
        rate_repo,
        reset_repo,
        verification_repo
    );

    // Try to access protected route with invalid JWT
    let req = test::TestRequest::get()
        .uri("/auth/me")
        .insert_header(("Authorization", "Bearer invalid.jwt.token"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
