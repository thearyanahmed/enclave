//! HTTP handlers for Axum authentication endpoints.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

use super::middleware::{extract_bearer_token, AuthenticatedUser};
use super::routes::AppState;
use crate::actions::{
    ChangePasswordAction, ForgotPasswordAction, LoginAction, LogoutAction, RefreshTokenAction,
    ResetPasswordAction, SignupAction, UpdateUserAction, VerifyEmailAction,
};
use crate::api::{
    AuthResponse, ChangePasswordRequest, ErrorResponse, ForgotPasswordRequest, LoginRequest,
    MessageResponse, RefreshTokenRequest, RegisterRequest, ResetPasswordRequest, TokenResponse,
    UpdateUserRequest, UserResponse, VerifyEmailRequest,
};
use crate::{
    AuthError, EmailVerificationRepository, PasswordResetRepository, RateLimiterRepository,
    SecretString, StatefulTokenRepository, TokenRepository, UserRepository,
};

/// Register a new user.
///
/// POST /register
pub async fn register<U, T, R, P, E>(
    State(state): State<AppState<U, T, R, P, E>>,
    Json(body): Json<RegisterRequest>,
) -> impl IntoResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    P: Clone + Send + Sync + 'static,
    E: Clone + Send + Sync + 'static,
{
    let action = SignupAction::new(state.user_repo);
    let password = SecretString::new(&body.password);

    match action.execute(&body.email, &password).await {
        Ok(user) => (StatusCode::CREATED, Json(UserResponse::from(user))).into_response(),
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            (StatusCode::BAD_REQUEST, Json(error_response)).into_response()
        }
    }
}

/// Authenticate a user and return an access token.
///
/// POST /login
pub async fn login<U, T, R, P, E>(
    State(state): State<AppState<U, T, R, P, E>>,
    Json(body): Json<LoginRequest>,
) -> impl IntoResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    R: RateLimiterRepository + Clone + Send + Sync + 'static,
    P: Clone + Send + Sync + 'static,
    E: Clone + Send + Sync + 'static,
{
    let action = LoginAction::new(state.user_repo, state.token_repo, state.rate_limiter);
    let password = SecretString::new(&body.password);

    match action.execute(&body.email, &password).await {
        Ok((user, token)) => (
            StatusCode::OK,
            Json(AuthResponse {
                user: UserResponse::from(user),
                token: token.token,
                expires_at: token.expires_at,
            }),
        )
            .into_response(),
        Err(err) => {
            let error_response = ErrorResponse::from(err.clone());
            let status = match err {
                AuthError::TooManyAttempts => StatusCode::TOO_MANY_REQUESTS,
                AuthError::InvalidEmail | AuthError::InvalidPassword | AuthError::Validation(_) => {
                    StatusCode::BAD_REQUEST
                }
                AuthError::InvalidCredentials | AuthError::UserNotFound => StatusCode::UNAUTHORIZED,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (status, Json(error_response)).into_response()
        }
    }
}

/// Revoke the current access token.
///
/// POST /logout
pub async fn logout<U, T, R, P, E>(
    State(state): State<AppState<U, T, R, P, E>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse
where
    U: Clone + Send + Sync + 'static,
    T: StatefulTokenRepository + Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    P: Clone + Send + Sync + 'static,
    E: Clone + Send + Sync + 'static,
{
    let token = match extract_bearer_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "missing authorization token".to_owned(),
                }),
            )
                .into_response();
        }
    };

    let action = LogoutAction::new(state.token_repo);

    match action.execute(&token).await {
        Ok(()) => (
            StatusCode::OK,
            Json(MessageResponse {
                message: "Successfully logged out".to_owned(),
            }),
        )
            .into_response(),
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            (StatusCode::BAD_REQUEST, Json(error_response)).into_response()
        }
    }
}

/// Request a password reset token.
///
/// POST /forgot-password
#[cfg(feature = "rate_limit")]
pub async fn forgot_password<U, T, R, P, E>(
    State(state): State<AppState<U, T, R, P, E>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<ForgotPasswordRequest>,
) -> impl IntoResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    P: PasswordResetRepository + Clone + Send + Sync + 'static,
    E: Clone + Send + Sync + 'static,
{
    let action = ForgotPasswordAction::new(state.user_repo, state.password_reset);

    let client_ip = extract_client_ip(&headers);

    // Don't reveal whether user exists - always return success regardless of result
    let _ = action.execute(&body.email, &client_ip).await;

    (
        StatusCode::OK,
        Json(MessageResponse {
            message: "If the email exists, a password reset link has been sent".to_owned(),
        }),
    )
}

/// Request a password reset token.
///
/// POST /forgot-password
#[cfg(not(feature = "rate_limit"))]
pub async fn forgot_password<U, T, R, P, E>(
    State(state): State<AppState<U, T, R, P, E>>,
    Json(body): Json<ForgotPasswordRequest>,
) -> impl IntoResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    P: PasswordResetRepository + Clone + Send + Sync + 'static,
    E: Clone + Send + Sync + 'static,
{
    let action = ForgotPasswordAction::new(state.user_repo, state.password_reset);

    // Don't reveal whether user exists - always return success regardless of result
    let _ = action.execute(&body.email).await;

    (
        StatusCode::OK,
        Json(MessageResponse {
            message: "If the email exists, a password reset link has been sent".to_owned(),
        }),
    )
}

/// Reset a password using a reset token.
///
/// POST /reset-password
pub async fn reset_password<U, T, R, P, E>(
    State(state): State<AppState<U, T, R, P, E>>,
    Json(body): Json<ResetPasswordRequest>,
) -> impl IntoResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    P: PasswordResetRepository + Clone + Send + Sync + 'static,
    E: Clone + Send + Sync + 'static,
{
    let action = ResetPasswordAction::new(state.user_repo, state.password_reset);
    let password = SecretString::new(&body.password);

    match action.execute(&body.token, &password).await {
        Ok(()) => (
            StatusCode::OK,
            Json(MessageResponse {
                message: "Password has been reset successfully".to_owned(),
            }),
        )
            .into_response(),
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            (StatusCode::BAD_REQUEST, Json(error_response)).into_response()
        }
    }
}

/// Refresh an access token.
///
/// POST /refresh-token
pub async fn refresh_token<U, T, R, P, E>(
    State(state): State<AppState<U, T, R, P, E>>,
    Json(body): Json<RefreshTokenRequest>,
) -> impl IntoResponse
where
    U: Clone + Send + Sync + 'static,
    T: StatefulTokenRepository + Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    P: Clone + Send + Sync + 'static,
    E: Clone + Send + Sync + 'static,
{
    let action = RefreshTokenAction::new(state.token_repo);

    match action.execute(&body.token).await {
        Ok(new_token) => (
            StatusCode::OK,
            Json(TokenResponse {
                token: new_token.token,
                expires_at: new_token.expires_at,
            }),
        )
            .into_response(),
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            (StatusCode::UNAUTHORIZED, Json(error_response)).into_response()
        }
    }
}

/// Verify an email address using a verification token.
///
/// POST /verify-email
pub async fn verify_email<U, T, R, P, E>(
    State(state): State<AppState<U, T, R, P, E>>,
    Json(body): Json<VerifyEmailRequest>,
) -> impl IntoResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    P: Clone + Send + Sync + 'static,
    E: EmailVerificationRepository + Clone + Send + Sync + 'static,
{
    let action = VerifyEmailAction::new(state.user_repo, state.email_verification);

    match action.execute(&body.token).await {
        Ok(()) => (
            StatusCode::OK,
            Json(MessageResponse {
                message: "Email verified successfully".to_owned(),
            }),
        )
            .into_response(),
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            (StatusCode::BAD_REQUEST, Json(error_response)).into_response()
        }
    }
}

/// Get the current authenticated user.
///
/// GET /me
pub async fn get_current_user<U, T, R, P, E>(
    user: AuthenticatedUser<U, T>,
) -> impl IntoResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    P: Clone + Send + Sync + 'static,
    E: Clone + Send + Sync + 'static,
{
    Json(UserResponse::from(user.into_inner()))
}

/// Update the current authenticated user.
///
/// PUT /me
pub async fn update_user<U, T, R, P, E>(
    State(state): State<AppState<U, T, R, P, E>>,
    user: AuthenticatedUser<U, T>,
    Json(body): Json<UpdateUserRequest>,
) -> impl IntoResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    P: Clone + Send + Sync + 'static,
    E: Clone + Send + Sync + 'static,
{
    let action = UpdateUserAction::new(state.user_repo);

    match action
        .execute(user.user().id, &body.name, &body.email)
        .await
    {
        Ok(updated_user) => (StatusCode::OK, Json(UserResponse::from(updated_user))).into_response(),
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            (StatusCode::BAD_REQUEST, Json(error_response)).into_response()
        }
    }
}

/// Change the current user's password.
///
/// POST /change-password
pub async fn change_password<U, T, R, P, E>(
    State(state): State<AppState<U, T, R, P, E>>,
    user: AuthenticatedUser<U, T>,
    Json(body): Json<ChangePasswordRequest>,
) -> impl IntoResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    P: Clone + Send + Sync + 'static,
    E: Clone + Send + Sync + 'static,
{
    let action = ChangePasswordAction::new(state.user_repo);
    let current_password = SecretString::new(&body.current_password);
    let new_password = SecretString::new(&body.new_password);

    match action
        .execute(user.user().id, &current_password, &new_password)
        .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(MessageResponse {
                message: "Password changed successfully".to_owned(),
            }),
        )
            .into_response(),
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            (StatusCode::BAD_REQUEST, Json(error_response)).into_response()
        }
    }
}

// =============================================================================
// Magic Link handlers
// =============================================================================

/// Request a magic link for passwordless login.
///
/// POST /magic-link
#[cfg(all(feature = "magic_link", feature = "rate_limit"))]
pub async fn request_magic_link<U, T, R, P, E, M>(
    State(state): State<AppState<U, T, R, P, E>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<crate::api::MagicLinkRequest>,
) -> impl IntoResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    P: Clone + Send + Sync + 'static,
    E: Clone + Send + Sync + 'static,
    M: crate::MagicLinkRepository + Clone + Send + Sync + 'static,
{
    // Magic link repo would need to be added to AppState or passed differently
    // For now, this is a placeholder showing the pattern
    let _ = (state, headers, body);

    (
        StatusCode::OK,
        Json(MessageResponse {
            message: "If the email exists, a login link has been sent".to_owned(),
        }),
    )
}

/// Request a magic link for passwordless login.
///
/// POST /magic-link
#[cfg(all(feature = "magic_link", not(feature = "rate_limit")))]
pub async fn request_magic_link<U, T, R, P, E, M>(
    State(state): State<AppState<U, T, R, P, E>>,
    Json(body): Json<crate::api::MagicLinkRequest>,
) -> impl IntoResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    P: Clone + Send + Sync + 'static,
    E: Clone + Send + Sync + 'static,
    M: crate::MagicLinkRepository + Clone + Send + Sync + 'static,
{
    // Magic link repo would need to be added to AppState or passed differently
    // For now, this is a placeholder showing the pattern
    let _ = (state, body);

    (
        StatusCode::OK,
        Json(MessageResponse {
            message: "If the email exists, a login link has been sent".to_owned(),
        }),
    )
}

/// Verify a magic link and log in.
///
/// POST /magic-link/verify
#[cfg(feature = "magic_link")]
pub async fn verify_magic_link<U, T, R, P, E, M>(
    State(state): State<AppState<U, T, R, P, E>>,
    Json(body): Json<crate::api::VerifyMagicLinkRequest>,
) -> impl IntoResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    P: Clone + Send + Sync + 'static,
    E: Clone + Send + Sync + 'static,
    M: crate::MagicLinkRepository + Clone + Send + Sync + 'static,
{
    // Magic link repo would need to be added to AppState or passed differently
    // For now, this is a placeholder showing the pattern
    let _ = (state, body);

    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: "magic link verification not implemented".to_owned(),
        }),
    )
}

// =============================================================================
// Helper functions
// =============================================================================

/// Extract the client IP address from request headers.
#[cfg(feature = "rate_limit")]
fn extract_client_ip(headers: &axum::http::HeaderMap) -> String {
    // Try X-Forwarded-For first (for proxied requests)
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(value) = forwarded.to_str() {
            // X-Forwarded-For can contain multiple IPs, take the first one
            if let Some(ip) = value.split(',').next() {
                return ip.trim().to_owned();
            }
        }
    }

    // Try X-Real-IP
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(value) = real_ip.to_str() {
            return value.to_owned();
        }
    }

    // Default to unknown
    "unknown".to_owned()
}
