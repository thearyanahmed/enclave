//! JWT (JSON Web Token) support for stateless authentication.
//!
//! This module provides JWT-based authentication as an alternative to opaque tokens.
//! Enable with the `jwt` feature flag.

mod claims;
mod config;
mod service;

pub use claims::JwtClaims;
pub use config::JwtConfig;
pub use service::JwtService;
