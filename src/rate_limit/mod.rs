//! Rate limiting module inspired by Laravel's rate limiting.
//!
//! This module provides a flexible, configurable rate limiting system that can be used
//! as middleware for HTTP endpoints or programmatically within your application.
//!
//! # Features
//!
//! - **Configurable limits**: Define max attempts and time windows
//! - **Multiple key strategies**: Rate limit by IP, user ID, or custom keys
//! - **Pluggable storage**: In-memory (default), `PostgreSQL`, or custom backends
//! - **Laravel-style API**: Familiar `RateLimiter::for_()` builder pattern
//!
//! # Example
//!
//! ```rust,ignore
//! use enclave::rate_limit::{RateLimiter, Limit, InMemoryStore};
//! use std::sync::Arc;
//!
//! // Create a rate limiter with rules
//! let store = Arc::new(InMemoryStore::new());
//! let limiter = RateLimiter::new(store)
//!     .for_("api", Limit::per_minute(60))
//!     .for_("login", Limit::per_minute(5).by_ip())
//!     .for_("uploads", Limit::per_hour(100).by_user());
//!
//! // Use with actix-web middleware
//! App::new()
//!     .wrap(limiter.throttle("api"))
//!     .route("/api/resource", web::get().to(handler))
//! ```

mod limit;
mod limiter;
mod store;

#[cfg(feature = "actix")]
mod middleware;

#[cfg(feature = "sqlx_postgres")]
mod postgres_store;

pub use limit::Limit;
pub use limiter::{RateLimitResult, RateLimiter};
#[cfg(feature = "actix")]
pub use middleware::{Throttle, UserId, extract_client_ip};
#[cfg(feature = "sqlx_postgres")]
pub use postgres_store::PostgresRateLimitStore;
pub use store::{InMemoryStore, RateLimitInfo, RateLimitStore};
