mod cors;
mod error;
mod handlers;
mod middleware;
mod routes;

#[cfg(feature = "teams")]
pub mod teams;

pub use cors::{custom as custom_cors, default as default_cors, permissive as permissive_cors};
pub use error::AppError;
pub use middleware::{AuthenticatedUser, extract_bearer_token};
#[cfg(feature = "magic_link")]
pub use routes::magic_link_routes;
pub use routes::{
    AppState, auth_routes, private_routes, public_routes, stateless_auth_routes,
    stateless_private_routes, stateless_public_routes,
};
