//! Axum HTTP API layer for authentication endpoints.
//!
//! This module provides Axum-based HTTP handlers, middleware, and route configuration
//! for the authentication system.
//!
//! # Features
//!
//! - Bearer token authentication via [`AuthenticatedUser`] extractor
//! - Stateful routes (with logout/refresh) via [`auth_routes`]
//! - Stateless routes (JWT-compatible) via [`stateless_auth_routes`]
//! - CORS configuration via [`cors`] module
//!
//! # Example
//!
//! ```rust,ignore
//! use axum::Router;
//! use enclave::api::axum::{auth_routes, AppState};
//!
//! let state = AppState {
//!     user_repo: user_repo.clone(),
//!     token_repo: token_repo.clone(),
//!     rate_limiter: rate_limiter.clone(),
//!     password_reset: password_reset.clone(),
//!     email_verification: email_verification.clone(),
//! };
//!
//! let app = Router::new()
//!     .nest("/auth", auth_routes())
//!     .with_state(state);
//! ```

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
