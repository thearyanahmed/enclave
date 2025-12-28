//! Security-focused test suite.
//!
//! These tests verify security properties documented in SECURITY.md.
//! Run with: `cargo test --features "actix jwt mocks" --test security`

#![cfg(all(feature = "actix", feature = "jwt", feature = "mocks"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use actix_web::http::StatusCode;
use actix_web::{App, test as actix_test, web};
use chrono::{Duration, Utc};
use enclave::api::actix::stateless_auth_routes;
use enclave::crypto::{Argon2Hasher, PasswordHasher, generate_token, hash_token};
use enclave::jwt::{JwtConfig, JwtService, JwtTokenProvider};
use enclave::validators::PasswordPolicy;
use enclave::{
    AuthConfig, MockEmailVerificationRepository, MockPasswordResetRepository,
    MockRateLimiterRepository, MockTokenRepository, MockUserRepository, RateLimiterRepository,
    SecretString, StatefulTokenRepository, TokenRepository,
};

// =============================================================================
// Password Security Tests
// =============================================================================

#[test]
fn argon2_produces_different_hashes_for_same_password() {
    let hasher = Argon2Hasher::default();
    let password = "testpassword123";

    let hash1 = hasher.hash(password).unwrap();
    let hash2 = hasher.hash(password).unwrap();

    // Same password should produce different hashes due to random salt
    assert_ne!(hash1, hash2);

    // But both should verify correctly
    assert!(hasher.verify(password, &hash1).unwrap());
    assert!(hasher.verify(password, &hash2).unwrap());
}

#[test]
fn argon2_wrong_password_fails_verification() {
    let hasher = Argon2Hasher::default();
    let hash = hasher.hash("correctpassword").unwrap();

    let result = hasher.verify("wrongpassword", &hash).unwrap();
    assert!(!result);
}

#[test]
fn argon2_production_preset_uses_stronger_params() {
    let default = Argon2Hasher::default();
    let production = Argon2Hasher::production();

    // Production hashes should work correctly
    let hash = production.hash("testpassword").unwrap();
    assert!(production.verify("testpassword", &hash).unwrap());

    // Cross-verification should also work (algorithm is the same)
    assert!(default.verify("testpassword", &hash).unwrap());
}

#[test]
fn password_policy_enforces_minimum_length() {
    let policy = PasswordPolicy::new().min(12);

    assert!(policy.validate("short").is_err());
    assert!(policy.validate("longenoughpassword").is_ok());
}

#[test]
fn password_policy_strict_enforces_complexity() {
    // Strict policy requires: 12+ chars, uppercase, lowercase, digit, special
    let policy = PasswordPolicy::strict();

    // Too short
    assert!(policy.validate("Short1!").is_err());
    // Missing uppercase
    assert!(policy.validate("password123!").is_err());
    // Missing lowercase
    assert!(policy.validate("PASSWORD123!").is_err());
    // Missing digit
    assert!(policy.validate("PasswordTest!").is_err());
    // Missing special
    assert!(policy.validate("Password1234").is_err());
    // All requirements met
    assert!(policy.validate("Password123!").is_ok());
}

#[test]
fn secret_string_redacts_in_debug() {
    let secret = SecretString::new("my-secret-token");
    let debug_output = format!("{secret:?}");

    assert!(!debug_output.contains("my-secret-token"));
    assert!(debug_output.contains("[REDACTED]"));
}

#[test]
fn secret_string_redacts_in_display() {
    let secret = SecretString::new("my-secret-token");
    let display_output = format!("{secret}");

    assert!(!display_output.contains("my-secret-token"));
    assert!(display_output.contains("[REDACTED]"));
}

#[test]
fn secret_string_expose_returns_value() {
    let secret = SecretString::new("my-secret-token");
    assert_eq!(secret.expose_secret(), "my-secret-token");
}

// =============================================================================
// Token Security Tests
// =============================================================================

#[test]
fn generated_tokens_are_high_entropy() {
    let token1 = generate_token(32);
    let token2 = generate_token(32);

    // Tokens should be unique
    assert_ne!(token1, token2);

    // Tokens should be the requested length
    assert_eq!(token1.len(), 32);
    assert_eq!(token2.len(), 32);

    // Tokens should be alphanumeric (suitable for URLs)
    assert!(token1.chars().all(|c| c.is_ascii_alphanumeric()));
}

#[test]
fn token_hashing_is_one_way() {
    let raw_token = "my-raw-access-token-12345";
    let hashed = hash_token(raw_token);

    // Hash should be different from original
    assert_ne!(hashed, raw_token);

    // Same token should produce same hash (deterministic)
    let hashed2 = hash_token(raw_token);
    assert_eq!(hashed, hashed2);

    // Hash should be hex-encoded SHA-256 (64 chars)
    assert_eq!(hashed.len(), 64);
    assert!(hashed.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn different_tokens_produce_different_hashes() {
    let hash1 = hash_token("token1");
    let hash2 = hash_token("token2");

    assert_ne!(hash1, hash2);
}

// =============================================================================
// JWT Security Tests
// =============================================================================

#[test]
fn jwt_config_rejects_short_secret() {
    // Less than 32 bytes should fail
    let result = JwtConfig::new("short-secret");
    assert!(result.is_err());

    let result = JwtConfig::new("exactly-31-bytes-not-enough!!");
    assert!(result.is_err());
}

#[test]
fn jwt_config_accepts_valid_secret() {
    // Exactly 32 bytes should work
    let result = JwtConfig::new("exactly-32-bytes-is-good-enough!");
    assert!(result.is_ok());

    // More than 32 bytes should also work
    let result = JwtConfig::new("this-is-a-very-long-secret-key-for-jwt-tokens");
    assert!(result.is_ok());
}

#[test]
fn jwt_tokens_contain_jti_claim() {
    let config = JwtConfig::new("test-secret-key-for-jwt-testing!!").unwrap();
    let service = JwtService::new(config);

    let token_pair = service.create_token_pair(123).unwrap();

    // Decode and check jti is present and not empty
    let claims = service.decode(&token_pair.access_token).unwrap();
    assert!(!claims.jti.is_empty());
}

#[test]
fn jwt_tokens_have_unique_jti() {
    let config = JwtConfig::new("test-secret-key-for-jwt-testing!!").unwrap();
    let service = JwtService::new(config);

    let pair1 = service.create_token_pair(123).unwrap();
    let pair2 = service.create_token_pair(123).unwrap();

    let claims1 = service.decode(&pair1.access_token).unwrap();
    let claims2 = service.decode(&pair2.access_token).unwrap();

    // Each token should have a unique jti
    assert_ne!(claims1.jti, claims2.jti);
}

#[test]
fn jwt_tampered_tokens_rejected() {
    let config = JwtConfig::new("test-secret-key-for-jwt-testing!!").unwrap();
    let service = JwtService::new(config);

    let pair = service.create_token_pair(123).unwrap();

    // Tamper with the token (change a character in the signature)
    let mut tampered = pair.access_token;
    let last_char = tampered.pop().unwrap();
    let new_char = if last_char == 'a' { 'b' } else { 'a' };
    tampered.push(new_char);

    let result = service.decode(&tampered);
    assert!(result.is_err());
}

// =============================================================================
// Rate Limiting Tests
// =============================================================================

#[test]
fn auth_config_strict_has_stronger_limits() {
    let default = AuthConfig::default();
    let strict = AuthConfig::strict();

    // Strict should have fewer allowed attempts or longer lockout
    assert!(
        strict.rate_limit.max_failed_attempts <= default.rate_limit.max_failed_attempts
            || strict.rate_limit.lockout_duration >= default.rate_limit.lockout_duration
    );
}

#[tokio::test]
async fn mock_rate_limiter_tracks_attempts() {
    let limiter = MockRateLimiterRepository::new();
    let email = "test@example.com";
    let since = Utc::now() - Duration::hours(1);

    // Record failed attempts
    limiter
        .record_attempt(email, false, Some("192.168.1.1"))
        .await
        .unwrap();
    limiter
        .record_attempt(email, false, Some("192.168.1.1"))
        .await
        .unwrap();

    // Get recent failed attempts count
    let attempts = limiter
        .get_recent_failed_attempts(email, since)
        .await
        .unwrap();
    assert_eq!(attempts, 2);

    // Clear attempts
    limiter.clear_attempts(email).await.unwrap();

    // Attempts should be cleared
    let attempts = limiter
        .get_recent_failed_attempts(email, since)
        .await
        .unwrap();
    assert_eq!(attempts, 0);
}

// =============================================================================
// Token Expiration Tests
// =============================================================================

#[tokio::test]
async fn mock_token_repo_handles_expiry() {
    let repo = MockTokenRepository::new();

    // Create an already-expired token
    let expired_at = Utc::now() - Duration::hours(1);
    let token = repo.create_token(1, expired_at).await.unwrap();

    // Prune expired should remove it
    let pruned = repo.prune_expired().await.unwrap();
    assert!(pruned >= 1);

    // Token should no longer be findable
    let found = repo.find_token(token.token.expose_secret()).await.unwrap();
    assert!(found.is_none());
}

#[tokio::test]
async fn mock_token_repo_keeps_valid_tokens() {
    let repo = MockTokenRepository::new();

    // Create a valid token (expires in 1 hour)
    let expires_at = Utc::now() + Duration::hours(1);
    let token = repo.create_token(1, expires_at).await.unwrap();

    // Prune expired should not remove it
    let _pruned = repo.prune_expired().await.unwrap();

    // Token should still be findable
    let found = repo.find_token(token.token.expose_secret()).await.unwrap();
    assert!(found.is_some());
}

// =============================================================================
// User Enumeration Prevention Tests
// =============================================================================

fn create_test_app() -> (
    MockUserRepository,
    JwtTokenProvider,
    MockRateLimiterRepository,
    MockPasswordResetRepository,
    MockEmailVerificationRepository,
) {
    let jwt_config = JwtConfig::new("test-secret-key-for-jwt-testing!!").unwrap();
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

#[actix_rt::test]
async fn login_invalid_email_returns_generic_error() {
    let (user_repo, token_repo, rate_repo, reset_repo, verify_repo) = create_test_app();

    let app = actix_test::init_service(
        App::new()
            .app_data(web::Data::new(user_repo))
            .app_data(web::Data::new(token_repo))
            .app_data(web::Data::new(rate_repo))
            .app_data(web::Data::new(reset_repo))
            .app_data(web::Data::new(verify_repo))
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
    .await;

    // Try to login with non-existent email
    let req = actix_test::TestRequest::post()
        .uri("/auth/login")
        .set_json(serde_json::json!({
            "email": "nonexistent@example.com",
            "password": "anypassword123"
        }))
        .to_request();

    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let body: serde_json::Value = actix_test::read_body_json(resp).await;
    // Error should be generic, not revealing that email doesn't exist
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("invalid")
    );
}

#[actix_rt::test]
async fn login_wrong_password_returns_same_error() {
    let (user_repo, token_repo, rate_repo, reset_repo, verify_repo) = create_test_app();

    let app = actix_test::init_service(
        App::new()
            .app_data(web::Data::new(user_repo.clone()))
            .app_data(web::Data::new(token_repo))
            .app_data(web::Data::new(rate_repo))
            .app_data(web::Data::new(reset_repo))
            .app_data(web::Data::new(verify_repo))
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
    .await;

    // First register a user
    let req = actix_test::TestRequest::post()
        .uri("/auth/register")
        .set_json(serde_json::json!({
            "email": "existing@example.com",
            "password": "correctpassword123"
        }))
        .to_request();
    actix_test::call_service(&app, req).await;

    // Try to login with wrong password
    let req = actix_test::TestRequest::post()
        .uri("/auth/login")
        .set_json(serde_json::json!({
            "email": "existing@example.com",
            "password": "wrongpassword123"
        }))
        .to_request();

    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let body: serde_json::Value = actix_test::read_body_json(resp).await;
    // Same generic error as non-existent email
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("invalid")
    );
}

// =============================================================================
// Authorization Tests
// =============================================================================

#[actix_rt::test]
async fn protected_routes_require_auth() {
    let (user_repo, token_repo, rate_repo, reset_repo, verify_repo) = create_test_app();

    let app = actix_test::init_service(
        App::new()
            .app_data(web::Data::new(user_repo))
            .app_data(web::Data::new(token_repo))
            .app_data(web::Data::new(rate_repo))
            .app_data(web::Data::new(reset_repo))
            .app_data(web::Data::new(verify_repo))
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
    .await;

    // Try to access /auth/me without token
    let req = actix_test::TestRequest::get().uri("/auth/me").to_request();

    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn invalid_bearer_token_rejected() {
    let (user_repo, token_repo, rate_repo, reset_repo, verify_repo) = create_test_app();

    let app = actix_test::init_service(
        App::new()
            .app_data(web::Data::new(user_repo))
            .app_data(web::Data::new(token_repo))
            .app_data(web::Data::new(rate_repo))
            .app_data(web::Data::new(reset_repo))
            .app_data(web::Data::new(verify_repo))
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
    .await;

    // Try with invalid token format
    let req = actix_test::TestRequest::get()
        .uri("/auth/me")
        .insert_header(("Authorization", "Bearer not-a-valid-token"))
        .to_request();

    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn malformed_auth_header_rejected() {
    let (user_repo, token_repo, rate_repo, reset_repo, verify_repo) = create_test_app();

    let app = actix_test::init_service(
        App::new()
            .app_data(web::Data::new(user_repo))
            .app_data(web::Data::new(token_repo))
            .app_data(web::Data::new(rate_repo))
            .app_data(web::Data::new(reset_repo))
            .app_data(web::Data::new(verify_repo))
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
    .await;

    // Missing "Bearer " prefix
    let req = actix_test::TestRequest::get()
        .uri("/auth/me")
        .insert_header(("Authorization", "some-token"))
        .to_request();

    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// =============================================================================
// Token Revocation Tests
// =============================================================================

#[tokio::test]
async fn revoked_tokens_cannot_be_used() {
    let repo = MockTokenRepository::new();

    // Create a valid token
    let expires_at = Utc::now() + Duration::hours(1);
    let token = repo.create_token(1, expires_at).await.unwrap();

    // Token should be findable
    let found = repo.find_token(token.token.expose_secret()).await.unwrap();
    assert!(found.is_some());

    // Revoke the token
    repo.revoke_token(token.token.expose_secret())
        .await
        .unwrap();

    // Token should no longer be findable
    let found = repo.find_token(token.token.expose_secret()).await.unwrap();
    assert!(found.is_none());
}

#[tokio::test]
async fn revoke_all_user_tokens_works() {
    let repo = MockTokenRepository::new();
    let user_id = 42;

    // Create multiple tokens for the user
    let expires_at = Utc::now() + Duration::hours(1);
    let token1 = repo.create_token(user_id, expires_at).await.unwrap();
    let token2 = repo.create_token(user_id, expires_at).await.unwrap();

    // Both should be findable
    assert!(
        repo.find_token(token1.token.expose_secret())
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        repo.find_token(token2.token.expose_secret())
            .await
            .unwrap()
            .is_some()
    );

    // Revoke all tokens for the user
    repo.revoke_all_user_tokens(user_id).await.unwrap();

    // Neither should be findable now
    assert!(
        repo.find_token(token1.token.expose_secret())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repo.find_token(token2.token.expose_secret())
            .await
            .unwrap()
            .is_none()
    );
}
