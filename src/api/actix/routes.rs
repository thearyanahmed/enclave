use actix_web::web;

#[cfg(feature = "magic_link")]
use crate::MagicLinkRepository;
use crate::{
    EmailVerificationRepository, PasswordResetRepository, RateLimiterRepository,
    StatefulTokenRepository, TokenRepository, UserRepository,
};

use super::handlers;

/// Configures all authentication routes under `/auth` scope.
///
/// This is the simplest way to add all auth routes. For custom middleware per route group,
/// use [`public_routes`] and [`private_routes`] separately.
///
/// Requires `web::Data` for all repository types to be registered in the app.
///
/// Note: `T` must implement [`StatefulTokenRepository`] because logout and refresh-token
/// endpoints require token revocation. For stateless tokens (JWT), use custom route
/// configuration without these endpoints.
pub fn auth_routes<U, T, R, P, E>(cfg: &mut web::ServiceConfig)
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: StatefulTokenRepository + Clone + Send + Sync + 'static,
    R: RateLimiterRepository + Clone + Send + Sync + 'static,
    P: PasswordResetRepository + Clone + Send + Sync + 'static,
    E: EmailVerificationRepository + Clone + Send + Sync + 'static,
{
    cfg.service(
        web::scope("/auth")
            .configure(public_routes::<U, T, R, P, E>)
            .configure(private_routes::<U, T>),
    );
}

/// Configures public authentication routes (no authentication required).
///
/// Routes:
/// - `POST /register` - User registration
/// - `POST /login` - User login
/// - `POST /forgot-password` - Request password reset
/// - `POST /reset-password` - Reset password with token
/// - `POST /refresh-token` - Refresh access token
/// - `POST /verify-email` - Verify email with token
pub fn public_routes<U, T, R, P, E>(cfg: &mut web::ServiceConfig)
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: StatefulTokenRepository + Clone + Send + Sync + 'static,
    R: RateLimiterRepository + Clone + Send + Sync + 'static,
    P: PasswordResetRepository + Clone + Send + Sync + 'static,
    E: EmailVerificationRepository + Clone + Send + Sync + 'static,
{
    cfg.route("/register", web::post().to(handlers::register::<U>))
        .route("/login", web::post().to(handlers::login::<U, T, R>))
        .route(
            "/forgot-password",
            web::post().to(handlers::forgot_password::<U, P>),
        )
        .route(
            "/reset-password",
            web::post().to(handlers::reset_password::<U, P>),
        )
        .route(
            "/refresh-token",
            web::post().to(handlers::refresh_token::<T>),
        )
        .route(
            "/verify-email",
            web::post().to(handlers::verify_email::<U, E>),
        );
}

/// Configures private authentication routes (authentication required).
///
/// These routes require a valid bearer token in the `Authorization` header.
///
/// Routes:
/// - `POST /logout` - Revoke current token
/// - `GET /me` - Get current user profile
/// - `PUT /me` - Update current user profile
/// - `POST /change-password` - Change password
pub fn private_routes<U, T>(cfg: &mut web::ServiceConfig)
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: StatefulTokenRepository + Clone + Send + Sync + 'static,
{
    cfg.route("/logout", web::post().to(handlers::logout::<T>))
        .route("/me", web::get().to(handlers::get_current_user::<U, T>))
        .route("/me", web::put().to(handlers::update_user::<U, T>))
        .route(
            "/change-password",
            web::post().to(handlers::change_password::<U, T>),
        );
}

// =============================================================================
// Stateless Token Routes (JWT)
// =============================================================================
//
// These routes are designed for stateless tokens like JWT where server-side
// token revocation is not possible. They exclude logout and refresh-token
// endpoints since those require stateful token storage.

/// Configures all authentication routes for stateless tokens (JWT) under `/auth` scope.
///
/// This is the JWT equivalent of [`auth_routes`]. It excludes logout and refresh-token
/// endpoints since JWT tokens cannot be revoked server-side.
///
/// For JWT token refresh, implement a separate refresh token mechanism using
/// `JwtService::refresh_access_token` directly.
pub fn stateless_auth_routes<U, T, R, P, E>(cfg: &mut web::ServiceConfig)
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    R: RateLimiterRepository + Clone + Send + Sync + 'static,
    P: PasswordResetRepository + Clone + Send + Sync + 'static,
    E: EmailVerificationRepository + Clone + Send + Sync + 'static,
{
    cfg.service(
        web::scope("/auth")
            .configure(stateless_public_routes::<U, T, R, P, E>)
            .configure(stateless_private_routes::<U, T>),
    );
}

/// Configures public routes for stateless tokens (no authentication required).
///
/// Routes:
/// - `POST /register` - User registration
/// - `POST /login` - User login
/// - `POST /forgot-password` - Request password reset
/// - `POST /reset-password` - Reset password with token
/// - `POST /verify-email` - Verify email with token
///
/// Note: No `/refresh-token` endpoint - JWT refresh should be handled separately.
pub fn stateless_public_routes<U, T, R, P, E>(cfg: &mut web::ServiceConfig)
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    R: RateLimiterRepository + Clone + Send + Sync + 'static,
    P: PasswordResetRepository + Clone + Send + Sync + 'static,
    E: EmailVerificationRepository + Clone + Send + Sync + 'static,
{
    cfg.route("/register", web::post().to(handlers::register::<U>))
        .route("/login", web::post().to(handlers::login::<U, T, R>))
        .route(
            "/forgot-password",
            web::post().to(handlers::forgot_password::<U, P>),
        )
        .route(
            "/reset-password",
            web::post().to(handlers::reset_password::<U, P>),
        )
        .route(
            "/verify-email",
            web::post().to(handlers::verify_email::<U, E>),
        );
}

/// Configures private routes for stateless tokens (authentication required).
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
pub fn stateless_private_routes<U, T>(cfg: &mut web::ServiceConfig)
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
{
    cfg.route("/me", web::get().to(handlers::get_current_user::<U, T>))
        .route("/me", web::put().to(handlers::update_user::<U, T>))
        .route(
            "/change-password",
            web::post().to(handlers::change_password::<U, T>),
        );
}

// =============================================================================
// Magic Link Routes
// =============================================================================
//
// These routes are for passwordless magic link authentication.
// Requires the `magic_link` feature flag to be enabled.

/// Configures magic link authentication routes.
///
/// Routes:
/// - `POST /magic-link` - Request magic link
/// - `POST /magic-link/verify` - Verify magic link and login
///
/// These routes can be added to an existing auth scope:
///
/// ```rust,ignore
/// use enclave::api::actix::{auth_routes, magic_link_routes};
///
/// App::new().service(
///     web::scope("/auth")
///         .configure(auth_routes::<...>)
///         .configure(magic_link_routes::<U, T, M>)
/// )
/// ```
#[cfg(feature = "magic_link")]
pub fn magic_link_routes<U, T, M>(cfg: &mut web::ServiceConfig)
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    M: MagicLinkRepository + Clone + Send + Sync + 'static,
{
    cfg.route(
        "/magic-link",
        web::post().to(handlers::request_magic_link::<U, M>),
    )
    .route(
        "/magic-link/verify",
        web::post().to(handlers::verify_magic_link::<U, T, M>),
    );
}
