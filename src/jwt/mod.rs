//! JWT (JSON Web Token) support for stateless authentication.
//!
//! This module provides JWT-based authentication as an alternative to opaque tokens.
//! Enable with the `jwt` feature flag.
//!
//! # Example
//!
//! ```ignore
//! use enclave::jwt::{JwtConfig, JwtService, JwtTokenProvider};
//!
//! // Create JWT configuration
//! let config = JwtConfig::new("your-secret-key")
//!     .with_expiry(chrono::Duration::hours(1));
//!
//! // Create service and provider
//! let service = JwtService::new(config);
//! let provider = JwtTokenProvider::new(service);
//!
//! // Use provider in your app (same interface as opaque tokens)
//! let token = provider.create_token(user_id).await?;
//! let validated = provider.validate_token(&token.token).await?;
//! ```

mod claims;
mod config;
mod provider;
mod service;

pub use claims::JwtClaims;
pub use config::JwtConfig;
pub use provider::JwtTokenProvider;
pub use service::JwtService;
