//! End-to-end tests for the Axum HTTP API layer.
//!
//! These tests use mock repositories - no database required.
//! Run with: `cargo test --features "axum_api mocks" --test e2e_axum`

#![cfg(all(feature = "axum_api", feature = "mocks"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use enclave::api::axum::{AppState, auth_routes};
use enclave::{
    MockEmailVerificationRepository, MockPasswordResetRepository, MockRateLimiterRepository,
    MockTokenRepository, MockUserRepository,
};
use http_body_util::BodyExt;
use tower::ServiceExt;

fn create_app() -> Router {
    let state = AppState {
        user_repo: MockUserRepository::new(),
        token_repo: MockTokenRepository::new(),
        rate_limiter: MockRateLimiterRepository::new(),
        password_reset: MockPasswordResetRepository::new(),
        email_verification: MockEmailVerificationRepository::new(),
    };

    Router::new()
        .nest(
            "/auth",
            auth_routes::<
                MockUserRepository,
                MockTokenRepository,
                MockRateLimiterRepository,
                MockPasswordResetRepository,
                MockEmailVerificationRepository,
            >(),
        )
        .with_state(state)
}

async fn body_to_json(body: Body) -> serde_json::Value {
    let bytes = body.collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn test_register_success() {
    let app = create_app();

    let request = Request::builder()
        .method("POST")
        .uri("/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "email": "test@example.com",
                "password": "securepassword123"
            }))
            .unwrap(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = body_to_json(response.into_body()).await;
    assert_eq!(body["email"], "test@example.com");
}

#[tokio::test]
async fn test_register_invalid_email() {
    let app = create_app();

    let request = Request::builder()
        .method("POST")
        .uri("/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "email": "notanemail",
                "password": "securepassword123"
            }))
            .unwrap(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = body_to_json(response.into_body()).await;
    assert!(body["error"].as_str().unwrap().contains("email"));
}

#[tokio::test]
async fn test_register_password_too_short() {
    let app = create_app();

    let request = Request::builder()
        .method("POST")
        .uri("/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "email": "test@example.com",
                "password": "short"
            }))
            .unwrap(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_login_success() {
    let app = create_app();

    // Register
    let request = Request::builder()
        .method("POST")
        .uri("/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "email": "login@example.com",
                "password": "securepassword123"
            }))
            .unwrap(),
        ))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Login
    let request = Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "email": "login@example.com",
                "password": "securepassword123"
            }))
            .unwrap(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = body_to_json(response.into_body()).await;
    assert!(body["token"].as_str().is_some());
    assert_eq!(body["user"]["email"], "login@example.com");
}

#[tokio::test]
async fn test_login_invalid_credentials() {
    let app = create_app();

    let request = Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "email": "nonexistent@example.com",
                "password": "wrongpassword"
            }))
            .unwrap(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_get_me_authenticated() {
    let app = create_app();

    // Register
    let request = Request::builder()
        .method("POST")
        .uri("/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "email": "me@example.com",
                "password": "securepassword123"
            }))
            .unwrap(),
        ))
        .unwrap();
    app.clone().oneshot(request).await.unwrap();

    // Login to get token
    let request = Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "email": "me@example.com",
                "password": "securepassword123"
            }))
            .unwrap(),
        ))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    let body = body_to_json(response.into_body()).await;
    let token = body["token"].as_str().unwrap();

    // Get /me with token
    let request = Request::builder()
        .method("GET")
        .uri("/auth/me")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = body_to_json(response.into_body()).await;
    assert_eq!(body["email"], "me@example.com");
}

#[tokio::test]
async fn test_get_me_unauthenticated() {
    let app = create_app();

    let request = Request::builder()
        .method("GET")
        .uri("/auth/me")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_logout() {
    let app = create_app();

    // Register
    let request = Request::builder()
        .method("POST")
        .uri("/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "email": "logout@example.com",
                "password": "securepassword123"
            }))
            .unwrap(),
        ))
        .unwrap();
    app.clone().oneshot(request).await.unwrap();

    // Login
    let request = Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "email": "logout@example.com",
                "password": "securepassword123"
            }))
            .unwrap(),
        ))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    let body = body_to_json(response.into_body()).await;
    let token = body["token"].as_str().unwrap().to_owned();

    // Logout
    let request = Request::builder()
        .method("POST")
        .uri("/auth/logout")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Try to use token again - should fail
    let request = Request::builder()
        .method("GET")
        .uri("/auth/me")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_update_user() {
    let app = create_app();

    // Register
    let request = Request::builder()
        .method("POST")
        .uri("/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "email": "update@example.com",
                "password": "securepassword123"
            }))
            .unwrap(),
        ))
        .unwrap();
    app.clone().oneshot(request).await.unwrap();

    // Login
    let request = Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "email": "update@example.com",
                "password": "securepassword123"
            }))
            .unwrap(),
        ))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    let body = body_to_json(response.into_body()).await;
    let token = body["token"].as_str().unwrap();

    // Update user
    let request = Request::builder()
        .method("PUT")
        .uri("/auth/me")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "name": "Updated Name",
                "email": "updated@example.com"
            }))
            .unwrap(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = body_to_json(response.into_body()).await;
    assert_eq!(body["name"], "Updated Name");
    assert_eq!(body["email"], "updated@example.com");
}

#[tokio::test]
async fn test_change_password() {
    let app = create_app();

    // Register
    let request = Request::builder()
        .method("POST")
        .uri("/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "email": "changepw@example.com",
                "password": "oldpassword123"
            }))
            .unwrap(),
        ))
        .unwrap();
    app.clone().oneshot(request).await.unwrap();

    // Login
    let request = Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "email": "changepw@example.com",
                "password": "oldpassword123"
            }))
            .unwrap(),
        ))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    let body = body_to_json(response.into_body()).await;
    let token = body["token"].as_str().unwrap();

    // Change password
    let request = Request::builder()
        .method("POST")
        .uri("/auth/change-password")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "current_password": "oldpassword123",
                "new_password": "newpassword456"
            }))
            .unwrap(),
        ))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Login with new password
    let request = Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "email": "changepw@example.com",
                "password": "newpassword456"
            }))
            .unwrap(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_forgot_password_always_returns_ok() {
    let app = create_app();

    // Should return OK even for non-existent email (security: don't reveal if email exists)
    let request = Request::builder()
        .method("POST")
        .uri("/auth/forgot-password")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "email": "nonexistent@example.com"
            }))
            .unwrap(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
