use actix_web::web;

use super::session_handlers::{session_get_user, session_login, session_logout};
use crate::session::SessionRepository;
use crate::{RateLimiterRepository, UserRepository};

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

pub fn session_public_routes<U, S, R>(cfg: &mut web::ServiceConfig)
where
    U: UserRepository + Clone + 'static,
    S: SessionRepository + Clone + 'static,
    R: RateLimiterRepository + Clone + 'static,
{
    cfg.route("/login", web::post().to(session_login::<U, S, R>));
}

pub fn session_private_routes<S>(cfg: &mut web::ServiceConfig)
where
    S: SessionRepository + Clone + 'static,
{
    cfg.route("/logout", web::post().to(session_logout::<S>))
        .route("/me", web::get().to(session_get_user::<S>));
}
