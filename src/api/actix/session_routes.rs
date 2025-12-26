//! Session-based authentication routes.

use actix_web::web;

use super::session_handlers::{session_get_user, session_login, session_logout};
use crate::session::SessionRepository;
use crate::{RateLimiterRepository, UserRepository};

/// Configures all session authentication routes under `/auth` scope.
///
/// # Routes
///
/// - `POST /auth/login` - Login and create session
/// - `POST /auth/logout` - Logout and destroy session
/// - `GET /auth/me` - Get current user from session
///
/// # Example
///
/// ```rust,ignore
/// use enclave::session::{InMemorySessionRepository, SessionConfig};
/// use enclave::api::actix::session_auth_routes;
///
/// App::new()
///     .app_data(web::Data::new(user_repo))
///     .app_data(web::Data::new(session_repo))
///     .app_data(web::Data::new(rate_limiter))
///     .app_data(web::Data::new(session_config))
///     .configure(session_auth_routes::<UserRepo, SessionRepo, RateLimiter>)
/// ```
pub fn session_auth_routes<U, S, R>(cfg: &mut web::ServiceConfig)
where
    U: UserRepository + Clone + 'static,
    S: SessionRepository + Clone + 'static,
    R: RateLimiterRepository + Clone + 'static,
{
    cfg.service(
        web::scope("/auth")
            .configure(session_public_routes::<U, S, R>)
            .configure(session_private_routes::<S>),
    );
}

/// Public session routes (no authentication required).
///
/// - `POST /login` - Login and create session
pub fn session_public_routes<U, S, R>(cfg: &mut web::ServiceConfig)
where
    U: UserRepository + Clone + 'static,
    S: SessionRepository + Clone + 'static,
    R: RateLimiterRepository + Clone + 'static,
{
    cfg.route("/login", web::post().to(session_login::<U, S, R>));
}

/// Private session routes (authentication required).
///
/// - `POST /logout` - Logout and destroy session
/// - `GET /me` - Get current user from session
pub fn session_private_routes<S>(cfg: &mut web::ServiceConfig)
where
    S: SessionRepository + Clone + 'static,
{
    cfg.route("/logout", web::post().to(session_logout::<S>))
        .route("/me", web::get().to(session_get_user::<S>));
}
