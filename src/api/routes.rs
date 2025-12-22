use actix_web::web;

use crate::{RateLimiterRepository, TokenRepository, UserRepository};

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
///
/// App::new()
///     .app_data(web::Data::new(user_repo))
///     .app_data(web::Data::new(token_repo))
///     .app_data(web::Data::new(rate_limiter))
///     .configure(configure::<MyUserRepository, MyTokenRepository, MyRateLimiter>);
/// ```
pub fn configure<U, T, R>(cfg: &mut web::ServiceConfig)
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    R: RateLimiterRepository + Clone + Send + Sync + 'static,
{
    cfg.service(
        web::scope("/auth")
            .route("/register", web::post().to(handlers::register::<U, T, R>))
            .route("/login", web::post().to(handlers::login::<U, T, R>)),
    );
}
