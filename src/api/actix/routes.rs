use actix_web::web;

use super::handlers;
#[cfg(feature = "magic_link")]
use crate::MagicLinkRepository;
use crate::{
    EmailVerificationRepository, PasswordResetRepository, RateLimiterRepository,
    StatefulTokenRepository, TokenRepository, UserRepository,
};

/// requires `StatefulTokenRepository` for logout/refresh-token
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

/// excludes logout/refresh-token since JWT cannot be revoked server-side
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
