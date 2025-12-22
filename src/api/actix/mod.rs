pub mod cors;
mod handlers;
mod middleware;
mod routes;

pub use middleware::{AuthenticatedUser, AuthenticationError, extract_bearer_token};
pub use routes::{auth_routes, private_routes, public_routes};
