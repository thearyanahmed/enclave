//! Configuration types for the enclave authentication library.
//!
//! This module provides centralized configuration for all authentication
//! features including token expiration, rate limiting, and token generation.
//!
//! # Example
//!
//! ```rust
//! use chrono::Duration;
//! use enclave::config::{AuthConfig, RateLimitConfig, TokenConfig};
//!
//! // Use defaults
//! let config = AuthConfig::default();
//!
//! // Or customize
//! let config = AuthConfig {
//!     tokens: TokenConfig {
//!         access_token_expiry: Duration::hours(1),
//!         refresh_token_expiry: Duration::days(14),
//!         ..Default::default()
//!     },
//!     rate_limit: RateLimitConfig {
//!         max_failed_attempts: 3,
//!         lockout_duration: Duration::minutes(30),
//!     },
//!     ..Default::default()
//! };
//! ```

use chrono::Duration;

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub tokens: TokenConfig,
    pub rate_limit: RateLimitConfig,
    /// 32 alphanumeric chars = ~190 bits of entropy. min 32, max 64.
    pub token_length: usize,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            tokens: TokenConfig::default(),
            rate_limit: RateLimitConfig::default(),
            token_length: 32,
        }
    }
}

impl AuthConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// shorter expiration, lenient rate limits
    pub fn development() -> Self {
        Self {
            tokens: TokenConfig {
                access_token_expiry: Duration::hours(24),
                refresh_token_expiry: Duration::days(7),
                password_reset_expiry: Duration::hours(2),
                email_verification_expiry: Duration::days(7),
                #[cfg(feature = "magic_link")]
                magic_link_expiry: Duration::minutes(30),
            },
            rate_limit: RateLimitConfig {
                max_failed_attempts: 10,
                lockout_duration: Duration::minutes(5),
            },
            token_length: 32,
        }
    }

    /// shorter token lifetimes, stricter rate limits
    pub fn strict() -> Self {
        Self {
            tokens: TokenConfig {
                access_token_expiry: Duration::hours(1),
                refresh_token_expiry: Duration::days(1),
                password_reset_expiry: Duration::minutes(30),
                email_verification_expiry: Duration::hours(12),
                #[cfg(feature = "magic_link")]
                magic_link_expiry: Duration::minutes(10),
            },
            rate_limit: RateLimitConfig {
                max_failed_attempts: 3,
                lockout_duration: Duration::minutes(30),
            },
            token_length: 48,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TokenConfig {
    pub access_token_expiry: Duration,
    pub refresh_token_expiry: Duration,
    pub password_reset_expiry: Duration,
    pub email_verification_expiry: Duration,
    #[cfg(feature = "magic_link")]
    pub magic_link_expiry: Duration,
}

impl Default for TokenConfig {
    fn default() -> Self {
        Self {
            access_token_expiry: Duration::days(7),
            refresh_token_expiry: Duration::days(30),
            password_reset_expiry: Duration::hours(1),
            email_verification_expiry: Duration::hours(24),
            #[cfg(feature = "magic_link")]
            magic_link_expiry: Duration::minutes(15),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub max_failed_attempts: u32,
    pub lockout_duration: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_failed_attempts: 5,
            lockout_duration: Duration::minutes(15),
        }
    }
}

impl RateLimitConfig {
    #[inline]
    pub fn lockout_duration_minutes(&self) -> i64 {
        self.lockout_duration.num_minutes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AuthConfig::default();

        assert_eq!(config.tokens.access_token_expiry, Duration::days(7));
        assert_eq!(config.tokens.refresh_token_expiry, Duration::days(30));
        assert_eq!(config.tokens.password_reset_expiry, Duration::hours(1));
        assert_eq!(config.tokens.email_verification_expiry, Duration::hours(24));
        assert_eq!(config.rate_limit.max_failed_attempts, 5);
        assert_eq!(config.rate_limit.lockout_duration, Duration::minutes(15));
        assert_eq!(config.token_length, 32);
    }

    #[test]
    fn test_strict_config() {
        let config = AuthConfig::strict();

        assert_eq!(config.tokens.access_token_expiry, Duration::hours(1));
        assert_eq!(config.rate_limit.max_failed_attempts, 3);
        assert_eq!(config.token_length, 48);
    }

    #[test]
    fn test_development_config() {
        let config = AuthConfig::development();

        assert_eq!(config.tokens.access_token_expiry, Duration::hours(24));
        assert_eq!(config.rate_limit.max_failed_attempts, 10);
    }

    #[test]
    fn test_lockout_duration_minutes() {
        let config = RateLimitConfig::default();
        assert_eq!(config.lockout_duration_minutes(), 15);
    }
}
