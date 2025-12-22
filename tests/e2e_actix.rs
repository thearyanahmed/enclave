//! End-to-end tests for the actix-web HTTP API layer.
//!
//! These tests use mock repositories - no database required.
//! Run with: `cargo test --features actix --test e2e_actix`

#![cfg(feature = "actix")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use actix_web::{App, http::StatusCode, test, web};
use std::sync::Arc;

use enclave::api::actix::auth_routes;
use enclave::{
    MockEmailVerificationRepository, MockPasswordResetRepository, MockRateLimiterRepository,
    MockTokenRepository, MockUserRepository,
};

type UserRepo = Arc<MockUserRepository>;
type TokenRepo = Arc<MockTokenRepository>;
type RateLimiterRepo = Arc<MockRateLimiterRepository>;
type PasswordResetRepo = Arc<MockPasswordResetRepository>;
type EmailVerificationRepo = Arc<MockEmailVerificationRepository>;

fn create_test_app() -> (
    UserRepo,
    TokenRepo,
    RateLimiterRepo,
    PasswordResetRepo,
    EmailVerificationRepo,
) {
    (
        Arc::new(MockUserRepository::new()),
        Arc::new(MockTokenRepository::new()),
        Arc::new(MockRateLimiterRepository::new()),
        Arc::new(MockPasswordResetRepository::new()),
        Arc::new(MockEmailVerificationRepository::new()),
    )
}

#[actix_rt::test]
async fn test_register_success() {
    let (user_repo, token_repo, rate_repo, reset_repo, verification_repo) = create_test_app();

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(user_repo))
            .app_data(web::Data::new(token_repo))
            .app_data(web::Data::new(rate_repo))
            .app_data(web::Data::new(reset_repo))
            .app_data(web::Data::new(verification_repo))
            .configure(auth_routes::<
                MockUserRepository,
                MockTokenRepository,
                MockRateLimiterRepository,
                MockPasswordResetRepository,
                MockEmailVerificationRepository,
            >),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/auth/register")
        .set_json(serde_json::json!({
            "email": "test@example.com",
            "password": "securepassword123"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["email"], "test@example.com");
}

#[actix_rt::test]
async fn test_register_invalid_email() {
    let (user_repo, token_repo, rate_repo, reset_repo, verification_repo) = create_test_app();

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(user_repo))
            .app_data(web::Data::new(token_repo))
            .app_data(web::Data::new(rate_repo))
            .app_data(web::Data::new(reset_repo))
            .app_data(web::Data::new(verification_repo))
            .configure(auth_routes::<
                MockUserRepository,
                MockTokenRepository,
                MockRateLimiterRepository,
                MockPasswordResetRepository,
                MockEmailVerificationRepository,
            >),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/auth/register")
        .set_json(serde_json::json!({
            "email": "notanemail",
            "password": "securepassword123"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["error"].as_str().unwrap().contains("email"));
}

#[actix_rt::test]
async fn test_register_password_too_short() {
    let (user_repo, token_repo, rate_repo, reset_repo, verification_repo) = create_test_app();

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(user_repo))
            .app_data(web::Data::new(token_repo))
            .app_data(web::Data::new(rate_repo))
            .app_data(web::Data::new(reset_repo))
            .app_data(web::Data::new(verification_repo))
            .configure(auth_routes::<
                MockUserRepository,
                MockTokenRepository,
                MockRateLimiterRepository,
                MockPasswordResetRepository,
                MockEmailVerificationRepository,
            >),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/auth/register")
        .set_json(serde_json::json!({
            "email": "test@example.com",
            "password": "short"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[actix_rt::test]
async fn test_login_success() {
    let (user_repo, token_repo, rate_repo, reset_repo, verification_repo) = create_test_app();

    // First register a user
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(user_repo.clone()))
            .app_data(web::Data::new(token_repo.clone()))
            .app_data(web::Data::new(rate_repo.clone()))
            .app_data(web::Data::new(reset_repo.clone()))
            .app_data(web::Data::new(verification_repo.clone()))
            .configure(auth_routes::<
                MockUserRepository,
                MockTokenRepository,
                MockRateLimiterRepository,
                MockPasswordResetRepository,
                MockEmailVerificationRepository,
            >),
    )
    .await;

    // Register
    let req = test::TestRequest::post()
        .uri("/auth/register")
        .set_json(serde_json::json!({
            "email": "login@example.com",
            "password": "securepassword123"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Login
    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(serde_json::json!({
            "email": "login@example.com",
            "password": "securepassword123"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["token"].as_str().is_some());
    assert_eq!(body["user"]["email"], "login@example.com");
}

#[actix_rt::test]
async fn test_login_invalid_credentials() {
    let (user_repo, token_repo, rate_repo, reset_repo, verification_repo) = create_test_app();

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(user_repo))
            .app_data(web::Data::new(token_repo))
            .app_data(web::Data::new(rate_repo))
            .app_data(web::Data::new(reset_repo))
            .app_data(web::Data::new(verification_repo))
            .configure(auth_routes::<
                MockUserRepository,
                MockTokenRepository,
                MockRateLimiterRepository,
                MockPasswordResetRepository,
                MockEmailVerificationRepository,
            >),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(serde_json::json!({
            "email": "nonexistent@example.com",
            "password": "wrongpassword"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn test_get_me_authenticated() {
    let (user_repo, token_repo, rate_repo, reset_repo, verification_repo) = create_test_app();

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(user_repo.clone()))
            .app_data(web::Data::new(token_repo.clone()))
            .app_data(web::Data::new(rate_repo.clone()))
            .app_data(web::Data::new(reset_repo.clone()))
            .app_data(web::Data::new(verification_repo.clone()))
            .configure(auth_routes::<
                MockUserRepository,
                MockTokenRepository,
                MockRateLimiterRepository,
                MockPasswordResetRepository,
                MockEmailVerificationRepository,
            >),
    )
    .await;

    // Register
    let req = test::TestRequest::post()
        .uri("/auth/register")
        .set_json(serde_json::json!({
            "email": "me@example.com",
            "password": "securepassword123"
        }))
        .to_request();
    test::call_service(&app, req).await;

    // Login to get token
    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(serde_json::json!({
            "email": "me@example.com",
            "password": "securepassword123"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    let token = body["token"].as_str().unwrap();

    // Get /me with token
    let req = test::TestRequest::get()
        .uri("/auth/me")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["email"], "me@example.com");
}

#[actix_rt::test]
async fn test_get_me_unauthenticated() {
    let (user_repo, token_repo, rate_repo, reset_repo, verification_repo) = create_test_app();

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(user_repo))
            .app_data(web::Data::new(token_repo))
            .app_data(web::Data::new(rate_repo))
            .app_data(web::Data::new(reset_repo))
            .app_data(web::Data::new(verification_repo))
            .configure(auth_routes::<
                MockUserRepository,
                MockTokenRepository,
                MockRateLimiterRepository,
                MockPasswordResetRepository,
                MockEmailVerificationRepository,
            >),
    )
    .await;

    let req = test::TestRequest::get().uri("/auth/me").to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn test_logout() {
    let (user_repo, token_repo, rate_repo, reset_repo, verification_repo) = create_test_app();

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(user_repo.clone()))
            .app_data(web::Data::new(token_repo.clone()))
            .app_data(web::Data::new(rate_repo.clone()))
            .app_data(web::Data::new(reset_repo.clone()))
            .app_data(web::Data::new(verification_repo.clone()))
            .configure(auth_routes::<
                MockUserRepository,
                MockTokenRepository,
                MockRateLimiterRepository,
                MockPasswordResetRepository,
                MockEmailVerificationRepository,
            >),
    )
    .await;

    // Register and login
    let req = test::TestRequest::post()
        .uri("/auth/register")
        .set_json(serde_json::json!({
            "email": "logout@example.com",
            "password": "securepassword123"
        }))
        .to_request();
    test::call_service(&app, req).await;

    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(serde_json::json!({
            "email": "logout@example.com",
            "password": "securepassword123"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    let token = body["token"].as_str().unwrap().to_owned();

    // Logout
    let req = test::TestRequest::post()
        .uri("/auth/logout")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Try to use token again - should fail
    let req = test::TestRequest::get()
        .uri("/auth/me")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn test_update_user() {
    let (user_repo, token_repo, rate_repo, reset_repo, verification_repo) = create_test_app();

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(user_repo.clone()))
            .app_data(web::Data::new(token_repo.clone()))
            .app_data(web::Data::new(rate_repo.clone()))
            .app_data(web::Data::new(reset_repo.clone()))
            .app_data(web::Data::new(verification_repo.clone()))
            .configure(auth_routes::<
                MockUserRepository,
                MockTokenRepository,
                MockRateLimiterRepository,
                MockPasswordResetRepository,
                MockEmailVerificationRepository,
            >),
    )
    .await;

    // Register and login
    let req = test::TestRequest::post()
        .uri("/auth/register")
        .set_json(serde_json::json!({
            "email": "update@example.com",
            "password": "securepassword123"
        }))
        .to_request();
    test::call_service(&app, req).await;

    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(serde_json::json!({
            "email": "update@example.com",
            "password": "securepassword123"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    let token = body["token"].as_str().unwrap();

    // Update user
    let req = test::TestRequest::put()
        .uri("/auth/me")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "name": "Updated Name",
            "email": "updated@example.com"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["name"], "Updated Name");
    assert_eq!(body["email"], "updated@example.com");
}

#[actix_rt::test]
async fn test_change_password() {
    let (user_repo, token_repo, rate_repo, reset_repo, verification_repo) = create_test_app();

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(user_repo.clone()))
            .app_data(web::Data::new(token_repo.clone()))
            .app_data(web::Data::new(rate_repo.clone()))
            .app_data(web::Data::new(reset_repo.clone()))
            .app_data(web::Data::new(verification_repo.clone()))
            .configure(auth_routes::<
                MockUserRepository,
                MockTokenRepository,
                MockRateLimiterRepository,
                MockPasswordResetRepository,
                MockEmailVerificationRepository,
            >),
    )
    .await;

    // Register and login
    let req = test::TestRequest::post()
        .uri("/auth/register")
        .set_json(serde_json::json!({
            "email": "changepw@example.com",
            "password": "oldpassword123"
        }))
        .to_request();
    test::call_service(&app, req).await;

    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(serde_json::json!({
            "email": "changepw@example.com",
            "password": "oldpassword123"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    let token = body["token"].as_str().unwrap();

    // Change password
    let req = test::TestRequest::post()
        .uri("/auth/change-password")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "current_password": "oldpassword123",
            "new_password": "newpassword456"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Login with new password
    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(serde_json::json!({
            "email": "changepw@example.com",
            "password": "newpassword456"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_rt::test]
async fn test_forgot_password_always_returns_ok() {
    let (user_repo, token_repo, rate_repo, reset_repo, verification_repo) = create_test_app();

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(user_repo))
            .app_data(web::Data::new(token_repo))
            .app_data(web::Data::new(rate_repo))
            .app_data(web::Data::new(reset_repo))
            .app_data(web::Data::new(verification_repo))
            .configure(auth_routes::<
                MockUserRepository,
                MockTokenRepository,
                MockRateLimiterRepository,
                MockPasswordResetRepository,
                MockEmailVerificationRepository,
            >),
    )
    .await;

    // Should return OK even for non-existent email (security: don't reveal if email exists)
    let req = test::TestRequest::post()
        .uri("/auth/forgot-password")
        .set_json(serde_json::json!({
            "email": "nonexistent@example.com"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}
