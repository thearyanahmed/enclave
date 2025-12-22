pub mod cors;
mod handlers;
#[cfg(feature = "jwt")]
mod jwt_middleware;
mod middleware;
mod routes;

#[cfg(feature = "jwt")]
pub use jwt_middleware::{JwtAuthenticatedUser, JwtAuthenticationError};
pub use middleware::{AuthenticatedUser, AuthenticationError, extract_bearer_token};
pub use routes::{auth_routes, private_routes, public_routes};
