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
//! // Create JWT configuration with short-lived access tokens
//! let config = JwtConfig::new("your-secret-key")
//!     .with_access_expiry(chrono::Duration::minutes(15))
//!     .with_refresh_expiry(chrono::Duration::days(7));
//!
//! // Create service and provider
//! let service = JwtService::new(config);
//! let provider = JwtTokenProvider::new(service.clone());
//!
//! // Create token pair (access + refresh)
//! let pair = service.create_token_pair(user_id)?;
//!
//! // Refresh access token when it expires
//! let new_access_token = service.refresh_access_token(&pair.refresh_token)?;
//! ```

mod claims;
mod config;
mod provider;
mod service;

pub use claims::{JwtClaims, TokenType};
pub use config::JwtConfig;
pub use provider::JwtTokenProvider;
pub use service::{JwtService, TokenPair};
