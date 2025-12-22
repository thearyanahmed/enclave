use actix_web::web;

use crate::{
    EmailVerificationRepository, PasswordResetRepository, RateLimiterRepository, TokenRepository,
    UserRepository,
};

use super::handlers;

/// Configures all authentication routes for the application.
///
/// # Example
/// ```ignore
/// use actix_web::{web, App};
/// use std::sync::Arc;
/// use enclave::api::configure;
///
/// let user_repo = Arc::new(MyUserRepository::new());
/// let token_repo = Arc::new(MyTokenRepository::new());
/// let rate_limiter = Arc::new(MyRateLimiter::new());
/// let reset_repo = Arc::new(MyPasswordResetRepository::new());
/// let verification_repo = Arc::new(MyEmailVerificationRepository::new());
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
            // Public routes
            .route("/register", web::post().to(handlers::register::<U, T, R, P, E>))
            .route("/login", web::post().to(handlers::login::<U, T, R, P, E>))
            .route("/forgot-password", web::post().to(handlers::forgot_password::<U, T, R, P, E>))
            .route("/reset-password", web::post().to(handlers::reset_password::<U, T, R, P, E>))
            .route("/refresh-token", web::post().to(handlers::refresh_token::<U, T, R, P, E>))
            .route("/verify-email", web::post().to(handlers::verify_email::<U, T, R, P, E>))
            // Authenticated routes
            .route("/logout", web::post().to(handlers::logout::<U, T, R, P, E>))
            .route("/me", web::get().to(handlers::get_current_user::<U, T, R, P, E>))
            .route("/me", web::put().to(handlers::update_user::<U, T, R, P, E>))
            .route("/change-password", web::post().to(handlers::change_password::<U, T, R, P, E>)),
    );
}
