use axum::Router;
use axum::routing::{get, post, put};

use super::handlers;
#[cfg(feature = "magic_link")]
use crate::MagicLinkRepository;
use crate::{
    EmailVerificationRepository, PasswordResetRepository, RateLimiterRepository,
    StatefulTokenRepository, TokenRepository, UserRepository,
};

#[derive(Clone)]
pub struct AppState<U, T, R, P, E> {
    pub user_repo: U,
    pub token_repo: T,
    pub rate_limiter: R,
    pub password_reset: P,
    pub email_verification: E,
}

/// requires `StatefulTokenRepository` for logout/refresh-token
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

/// excludes logout/refresh-token since JWT cannot be revoked server-side
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
