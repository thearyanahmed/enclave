//! Axum HTTP API layer for teams endpoints.
//!
//! This module provides Axum-based HTTP handlers, middleware, and route configuration
//! for team management.
//!
//! # Features
//!
//! - Team CRUD operations
//! - Team membership management
//! - Team invitation system
//! - User team context tracking
//!
//! # Example
//!
//! ```rust,ignore
//! use axum::Router;
//! use enclave::api::axum::teams::{teams_routes, context_routes, invitation_routes, TeamsState};
//!
//! let teams_state = TeamsState {
//!     user_repo: user_repo.clone(),
//!     token_repo: token_repo.clone(),
//!     team_repo: team_repo.clone(),
//!     membership_repo: membership_repo.clone(),
//!     invitation_repo: invitation_repo.clone(),
//!     context_repo: context_repo.clone(),
//! };
//!
//! let app = Router::new()
//!     .nest("/teams", teams_routes())
//!     .nest("/invitations", invitation_routes())
//!     .nest("/me/team", context_routes())
//!     .with_state(teams_state);
//! ```

mod handlers;
mod middleware;
mod routes;

pub use middleware::TeamsAuthenticatedUser;
pub use routes::{TeamsState, context_routes, invitation_routes, teams_routes};
