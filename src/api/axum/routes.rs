//! Route configuration for Axum authentication endpoints.

use axum::Router;
use axum::routing::{get, post, put};

#[cfg(feature = "magic_link")]
use crate::MagicLinkRepository;
use crate::{
    EmailVerificationRepository, PasswordResetRepository, RateLimiterRepository,
    StatefulTokenRepository, TokenRepository, UserRepository,
};

use super::handlers;

/// Application state containing all repository dependencies.
///
/// This struct holds all the repositories needed by the authentication handlers.
/// It is used as the state type for Axum routes.
#[derive(Clone)]
pub struct AppState<U, T, R, P, E> {
    /// User repository for user management operations.
    pub user_repo: U,
    /// Token repository for access token operations.
    pub token_repo: T,
    /// Rate limiter repository for tracking login attempts.
    pub rate_limiter: R,
    /// Password reset repository for password reset tokens.
    pub password_reset: P,
    /// Email verification repository for email verification tokens.
    pub email_verification: E,
}

/// Creates all authentication routes under `/auth` prefix.
///
/// This is the simplest way to add all auth routes. For custom middleware per route group,
/// use [`public_routes`] and [`private_routes`] separately.
///
/// Note: `T` must implement [`StatefulTokenRepository`] because logout and refresh-token
/// endpoints require token revocation. For stateless tokens (JWT), use
/// [`stateless_auth_routes`] instead.
pub fn auth_routes<U, T, R, P, E>() -> Router<AppState<U, T, R, P, E>>
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: StatefulTokenRepository + Clone + Send + Sync + 'static,
    R: RateLimiterRepository + Clone + Send + Sync + 'static,
    P: PasswordResetRepository + Clone + Send + Sync + 'static,
    E: EmailVerificationRepository + Clone + Send + Sync + 'static,
{
    Router::new().merge(public_routes()).merge(private_routes())
}

/// Creates public authentication routes (no authentication required).
///
/// Routes:
/// - `POST /register` - User registration
/// - `POST /login` - User login
/// - `POST /forgot-password` - Request password reset
/// - `POST /reset-password` - Reset password with token
/// - `POST /refresh-token` - Refresh access token
/// - `POST /verify-email` - Verify email with token
pub fn public_routes<U, T, R, P, E>() -> Router<AppState<U, T, R, P, E>>
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: StatefulTokenRepository + Clone + Send + Sync + 'static,
    R: RateLimiterRepository + Clone + Send + Sync + 'static,
    P: PasswordResetRepository + Clone + Send + Sync + 'static,
    E: EmailVerificationRepository + Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/register", post(handlers::register::<U, T, R, P, E>))
        .route("/login", post(handlers::login::<U, T, R, P, E>))
        .route(
            "/forgot-password",
            post(handlers::forgot_password::<U, T, R, P, E>),
        )
        .route(
            "/reset-password",
            post(handlers::reset_password::<U, T, R, P, E>),
        )
        .route(
            "/refresh-token",
            post(handlers::refresh_token::<U, T, R, P, E>),
        )
        .route(
            "/verify-email",
            post(handlers::verify_email::<U, T, R, P, E>),
        )
}

/// Creates private authentication routes (authentication required).
///
/// These routes require a valid bearer token in the `Authorization` header.
///
/// Routes:
/// - `POST /logout` - Revoke current token
/// - `GET /me` - Get current user profile
/// - `PUT /me` - Update current user profile
/// - `POST /change-password` - Change password
pub fn private_routes<U, T, R, P, E>() -> Router<AppState<U, T, R, P, E>>
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: StatefulTokenRepository + Clone + Send + Sync + 'static,
    R: RateLimiterRepository + Clone + Send + Sync + 'static,
    P: PasswordResetRepository + Clone + Send + Sync + 'static,
    E: EmailVerificationRepository + Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/logout", post(handlers::logout::<U, T, R, P, E>))
        .route("/me", get(handlers::get_current_user::<U, T, R, P, E>))
        .route("/me", put(handlers::update_user::<U, T, R, P, E>))
        .route(
            "/change-password",
            post(handlers::change_password::<U, T, R, P, E>),
        )
}

// =============================================================================
// Stateless Token Routes (JWT)
// =============================================================================
//
// These routes are designed for stateless tokens like JWT where server-side
// token revocation is not possible. They exclude logout and refresh-token
// endpoints since those require stateful token storage.

/// Creates all authentication routes for stateless tokens (JWT) under `/auth` prefix.
///
/// This is the JWT equivalent of [`auth_routes`]. It excludes logout and refresh-token
/// endpoints since JWT tokens cannot be revoked server-side.
///
/// For JWT token refresh, implement a separate refresh token mechanism using
/// `JwtService::refresh_access_token` directly.
pub fn stateless_auth_routes<U, T, R, P, E>() -> Router<AppState<U, T, R, P, E>>
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    R: RateLimiterRepository + Clone + Send + Sync + 'static,
    P: PasswordResetRepository + Clone + Send + Sync + 'static,
    E: EmailVerificationRepository + Clone + Send + Sync + 'static,
{
    Router::new()
        .merge(stateless_public_routes())
        .merge(stateless_private_routes())
}

/// Creates public routes for stateless tokens (no authentication required).
///
/// Routes:
/// - `POST /register` - User registration
/// - `POST /login` - User login
/// - `POST /forgot-password` - Request password reset
/// - `POST /reset-password` - Reset password with token
/// - `POST /verify-email` - Verify email with token
///
/// Note: No `/refresh-token` endpoint - JWT refresh should be handled separately.
pub fn stateless_public_routes<U, T, R, P, E>() -> Router<AppState<U, T, R, P, E>>
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    R: RateLimiterRepository + Clone + Send + Sync + 'static,
    P: PasswordResetRepository + Clone + Send + Sync + 'static,
    E: EmailVerificationRepository + Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/register", post(handlers::register::<U, T, R, P, E>))
        .route("/login", post(handlers::login::<U, T, R, P, E>))
        .route(
            "/forgot-password",
            post(handlers::forgot_password::<U, T, R, P, E>),
        )
        .route(
            "/reset-password",
            post(handlers::reset_password::<U, T, R, P, E>),
        )
        .route(
            "/verify-email",
            post(handlers::verify_email::<U, T, R, P, E>),
        )
}

/// Creates private routes for stateless tokens (authentication required).
///
/// These routes require a valid bearer token in the `Authorization` header.
///
/// Routes:
/// - `GET /me` - Get current user profile
/// - `PUT /me` - Update current user profile
/// - `POST /change-password` - Change password
///
/// Note: No `/logout` endpoint - JWT tokens cannot be revoked server-side.
/// Implement client-side token deletion or a token blocklist if needed.
pub fn stateless_private_routes<U, T, R, P, E>() -> Router<AppState<U, T, R, P, E>>
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    R: RateLimiterRepository + Clone + Send + Sync + 'static,
    P: PasswordResetRepository + Clone + Send + Sync + 'static,
    E: EmailVerificationRepository + Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/me", get(handlers::get_current_user::<U, T, R, P, E>))
        .route("/me", put(handlers::update_user::<U, T, R, P, E>))
        .route(
            "/change-password",
            post(handlers::change_password::<U, T, R, P, E>),
        )
}

// =============================================================================
// Magic Link Routes
// =============================================================================
//
// These routes are for passwordless magic link authentication.
// Requires the `magic_link` feature flag to be enabled.

/// Creates magic link authentication routes.
///
/// Routes:
/// - `POST /magic-link` - Request magic link
/// - `POST /magic-link/verify` - Verify magic link and login
///
/// These routes can be merged with existing auth routes:
///
/// ```rust,ignore
/// use enclave::api::axum::{auth_routes, magic_link_routes};
///
/// let app = Router::new()
///     .nest("/auth", auth_routes().merge(magic_link_routes()))
///     .with_state(state);
/// ```
#[cfg(feature = "magic_link")]
pub fn magic_link_routes<U, T, R, P, E, M>() -> Router<AppState<U, T, R, P, E>>
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    R: RateLimiterRepository + Clone + Send + Sync + 'static,
    P: PasswordResetRepository + Clone + Send + Sync + 'static,
    E: EmailVerificationRepository + Clone + Send + Sync + 'static,
    M: MagicLinkRepository + Clone + Send + Sync + 'static,
{
    Router::new()
        .route(
            "/magic-link",
            post(handlers::request_magic_link::<U, T, R, P, E, M>),
        )
        .route(
            "/magic-link/verify",
            post(handlers::verify_magic_link::<U, T, R, P, E, M>),
        )
}
