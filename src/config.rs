//! Configuration types for the enclave authentication library.
//!
//! This module provides centralized configuration for all authentication
//! features including token expiration, rate limiting, and token generation.
//!
//! # Example
//!
//! ```rust
//! use enclave::config::{EnclaveConfig, TokenConfig, RateLimitConfig};
//! use chrono::Duration;
//!
//! // Use defaults
//! let config = EnclaveConfig::default();
//!
//! // Or customize
//! let config = EnclaveConfig {
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

/// Main configuration struct for the enclave authentication library.
///
/// Contains all configurable settings that were previously hardcoded.
/// Use `EnclaveConfig::default()` for sensible production defaults.
#[derive(Debug, Clone)]
pub struct EnclaveConfig {
    /// Token expiration settings.
    pub tokens: TokenConfig,

    /// Rate limiting configuration.
    pub rate_limit: RateLimitConfig,

    /// Length of generated tokens (in characters).
    ///
    /// Default is 32 alphanumeric characters (~190 bits of entropy).
    /// Minimum recommended is 32, maximum is 64.
    pub token_length: usize,
}

impl Default for EnclaveConfig {
    fn default() -> Self {
        Self {
            tokens: TokenConfig::default(),
            rate_limit: RateLimitConfig::default(),
            token_length: 32,
        }
    }
}

impl EnclaveConfig {
    /// Creates a new configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a configuration suitable for development/testing.
    ///
    /// Uses shorter expiration times and more lenient rate limits.
    pub fn development() -> Self {
        Self {
            tokens: TokenConfig {
                access_token_expiry: Duration::hours(24),
                refresh_token_expiry: Duration::days(7),
                password_reset_expiry: Duration::hours(2),
                email_verification_expiry: Duration::days(7),
            },
            rate_limit: RateLimitConfig {
                max_failed_attempts: 10,
                lockout_duration: Duration::minutes(5),
            },
            token_length: 32,
        }
    }

    /// Creates a configuration with stricter security settings.
    ///
    /// Uses shorter token lifetimes and stricter rate limits.
    pub fn strict() -> Self {
        Self {
            tokens: TokenConfig {
                access_token_expiry: Duration::hours(1),
                refresh_token_expiry: Duration::days(1),
                password_reset_expiry: Duration::minutes(30),
                email_verification_expiry: Duration::hours(12),
            },
            rate_limit: RateLimitConfig {
                max_failed_attempts: 3,
                lockout_duration: Duration::minutes(30),
            },
            token_length: 48,
        }
    }
}

/// Configuration for token expiration times.
///
/// All durations are specified using `chrono::Duration`.
#[derive(Debug, Clone)]
pub struct TokenConfig {
    /// How long access tokens remain valid after creation.
    ///
    /// Default: 7 days
    pub access_token_expiry: Duration,

    /// How long refresh tokens remain valid.
    ///
    /// Default: 30 days
    pub refresh_token_expiry: Duration,

    /// How long password reset tokens remain valid.
    ///
    /// Default: 1 hour
    pub password_reset_expiry: Duration,

    /// How long email verification tokens remain valid.
    ///
    /// Default: 24 hours
    pub email_verification_expiry: Duration,
}

impl Default for TokenConfig {
    fn default() -> Self {
        Self {
            access_token_expiry: Duration::days(7),
            refresh_token_expiry: Duration::days(30),
            password_reset_expiry: Duration::hours(1),
            email_verification_expiry: Duration::hours(24),
        }
    }
}

/// Configuration for login rate limiting.
///
/// Controls how the system handles repeated failed login attempts
/// to prevent brute-force attacks.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum number of failed login attempts before lockout.
    ///
    /// Default: 5
    pub max_failed_attempts: u32,

    /// Duration of the lockout period after exceeding max attempts.
    ///
    /// Default: 15 minutes
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
    /// Returns the lockout duration in minutes.
    ///
    /// This is a convenience method for backwards compatibility.
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
        let config = EnclaveConfig::default();

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
        let config = EnclaveConfig::strict();

        assert_eq!(config.tokens.access_token_expiry, Duration::hours(1));
        assert_eq!(config.rate_limit.max_failed_attempts, 3);
        assert_eq!(config.token_length, 48);
    }

    #[test]
    fn test_development_config() {
        let config = EnclaveConfig::development();

        assert_eq!(config.tokens.access_token_expiry, Duration::hours(24));
        assert_eq!(config.rate_limit.max_failed_attempts, 10);
    }

    #[test]
    fn test_lockout_duration_minutes() {
        let config = RateLimitConfig::default();
        assert_eq!(config.lockout_duration_minutes(), 15);
    }
}
