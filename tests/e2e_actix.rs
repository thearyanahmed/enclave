//! End-to-end tests for the actix-web HTTP API layer.
//!
//! These tests use mock repositories - no database required.
//! Run with: `cargo test --features "actix mocks" --test e2e_actix`

#![cfg(all(feature = "actix", feature = "mocks"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use actix_web::http::StatusCode;
use actix_web::{App, test, web};
use enclave::api::actix::auth_routes;
use enclave::{
    MockEmailVerificationRepository, MockPasswordResetRepository, MockRateLimiterRepository,
    MockTokenRepository, MockUserRepository,
};

fn create_repos() -> (
    MockUserRepository,
    MockTokenRepository,
    MockRateLimiterRepository,
    MockPasswordResetRepository,
    MockEmailVerificationRepository,
) {
    (
        MockUserRepository::new(),
        MockTokenRepository::new(),
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
                    auth_routes::<
                        MockUserRepository,
                        MockTokenRepository,
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
async fn test_register_success() {
    let (user_repo, token_repo, rate_repo, reset_repo, verification_repo) = create_repos();
    let app = test_app!(
        user_repo,
        token_repo,
        rate_repo,
        reset_repo,
        verification_repo
    );

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
    let (user_repo, token_repo, rate_repo, reset_repo, verification_repo) = create_repos();
    let app = test_app!(
        user_repo,
        token_repo,
        rate_repo,
        reset_repo,
        verification_repo
    );

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
    let (user_repo, token_repo, rate_repo, reset_repo, verification_repo) = create_repos();
    let app = test_app!(
        user_repo,
        token_repo,
        rate_repo,
        reset_repo,
        verification_repo
    );

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
    let (user_repo, token_repo, rate_repo, reset_repo, verification_repo) = create_repos();
    let app = test_app!(
        user_repo,
        token_repo,
        rate_repo,
        reset_repo,
        verification_repo
    );

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
    let (user_repo, token_repo, rate_repo, reset_repo, verification_repo) = create_repos();
    let app = test_app!(
        user_repo,
        token_repo,
        rate_repo,
        reset_repo,
        verification_repo
    );

    let req = test::TestRequest::get().uri("/auth/me").to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn test_logout() {
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
    let (user_repo, token_repo, rate_repo, reset_repo, verification_repo) = create_repos();
    let app = test_app!(
        user_repo,
        token_repo,
        rate_repo,
        reset_repo,
        verification_repo
    );

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
