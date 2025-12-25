pub mod cors;
mod handlers;
mod middleware;
mod routes;

#[cfg(feature = "mocks")]
pub mod test_utils;

pub use middleware::{AuthenticatedUser, AuthenticationError, extract_bearer_token};
pub use routes::{
    auth_routes, private_routes, public_routes, stateless_auth_routes, stateless_private_routes,
    stateless_public_routes,
};
