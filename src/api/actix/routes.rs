use actix_web::web;

use crate::{
    EmailVerificationRepository, PasswordResetRepository, RateLimiterRepository, TokenRepository,
    UserRepository,
};

use super::handlers;

/// Configures all authentication routes under `/auth` scope.
///
/// This is the simplest way to add all auth routes. For custom middleware per route group,
/// use [`public_routes`] and [`private_routes`] separately.
///
/// # Example
/// ```ignore
/// use actix_web::{web, App};
/// use std::sync::Arc;
/// use enclave::api::actix::configure;
///
/// App::new()
///     .app_data(web::Data::new(user_repo))
///     .app_data(web::Data::new(token_repo))
///     .app_data(web::Data::new(rate_limiter))
///     .app_data(web::Data::new(reset_repo))
///     .app_data(web::Data::new(verification_repo))
///     .configure(configure::<MyUserRepo, MyTokenRepo, MyRateLimiter, MyResetRepo, MyVerificationRepo>);
/// ```
pub fn configure<U, T, R, P, E>(cfg: &mut web::ServiceConfig)
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
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
///
/// # Example
/// ```ignore
/// use actix_web::{web, App};
/// use enclave::api::actix::public_routes;
///
/// // With custom middleware
/// App::new()
///     .service(
///         web::scope("/auth")
///             .wrap(MyRateLimiter::new())
///             .configure(public_routes::<U, T, R, P, E>)
///     );
/// ```
pub fn public_routes<U, T, R, P, E>(cfg: &mut web::ServiceConfig)
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
/// Routes:
/// - `POST /logout` - Revoke current token
/// - `GET /me` - Get current user profile
/// - `PUT /me` - Update current user profile
/// - `POST /change-password` - Change password
///
/// # Example
/// ```ignore
/// use actix_web::{web, App};
/// use enclave::api::actix::private_routes;
///
/// // With custom middleware
/// App::new()
///     .service(
///         web::scope("/auth")
///             .wrap(MyAuditLogger::new())
///             .configure(private_routes::<U, T>)
///     );
/// ```
pub fn private_routes<U, T>(cfg: &mut web::ServiceConfig)
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
{
    cfg.route("/logout", web::post().to(handlers::logout::<T>))
        .route("/me", web::get().to(handlers::get_current_user::<U, T>))
        .route("/me", web::put().to(handlers::update_user::<U, T>))
        .route(
            "/change-password",
            web::post().to(handlers::change_password::<U, T>),
        );
}
