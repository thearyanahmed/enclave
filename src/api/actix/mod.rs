pub mod cors;
mod handlers;
mod middleware;
mod routes;

#[cfg(feature = "sessions")]
mod session_handlers;
#[cfg(feature = "sessions")]
mod session_middleware;
#[cfg(feature = "sessions")]
mod session_routes;

#[cfg(feature = "mocks")]
pub mod test_utils;

pub use middleware::{AuthenticatedUser, AuthenticationError, extract_bearer_token};
#[cfg(feature = "magic_link")]
pub use routes::magic_link_routes;
pub use routes::{
    auth_routes, private_routes, public_routes, stateless_auth_routes, stateless_private_routes,
    stateless_public_routes,
};
#[cfg(feature = "sessions")]
pub use session_handlers::SessionUserResponse;
#[cfg(feature = "sessions")]
pub use session_middleware::SessionAuthenticatedUser;
#[cfg(feature = "sessions")]
pub use session_routes::{session_auth_routes, session_private_routes, session_public_routes};
