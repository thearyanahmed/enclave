//! JWT (JSON Web Token) support for stateless authentication.
//!
//! This module provides JWT-based authentication as an alternative to opaque tokens.
//! Enable with the `jwt` feature flag.
//!
//! Key components:
//! - [`JwtConfig`] - Configuration for token expiry, issuer, and audience
//! - [`JwtService`] - Encodes/decodes tokens, creates token pairs, handles refresh
//! - [`JwtTokenProvider`] - Implements [`TokenRepository`] for use with existing handlers
//! - [`TokenPair`] - Contains access token, refresh token, and expiry info
//!
//! [`TokenRepository`]: crate::TokenRepository

mod claims;
mod config;
mod provider;
mod service;

pub use claims::{JwtClaims, TokenType};
pub use config::JwtConfig;
pub use provider::JwtTokenProvider;
pub use service::{JwtService, TokenPair};
