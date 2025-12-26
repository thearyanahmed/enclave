//! Session configuration.

use crate::SecretString;
use chrono::Duration;

/// SameSite cookie attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SameSite {
    /// Cookies are sent with every request (least secure).
    None,
    /// Cookies are sent with same-site requests and cross-site top-level navigations.
    Lax,
    /// Cookies are only sent with same-site requests (most secure).
    #[default]
    Strict,
}

/// Configuration for session-based authentication.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Name of the session cookie.
    pub cookie_name: String,
    /// Path for the session cookie.
    pub cookie_path: String,
    /// Domain for the session cookie.
    pub cookie_domain: Option<String>,
    /// Whether the cookie requires HTTPS.
    pub cookie_secure: bool,
    /// Whether the cookie is inaccessible to JavaScript.
    pub cookie_http_only: bool,
    /// SameSite attribute for the cookie.
    pub cookie_same_site: SameSite,
    /// Session lifetime (sliding window).
    pub session_lifetime: Duration,
    /// Secret key for HMAC signing.
    pub secret_key: SecretString,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            cookie_name: "enclave_session".to_owned(),
            cookie_path: "/".to_owned(),
            cookie_domain: None,
            cookie_secure: true,
            cookie_http_only: true,
            cookie_same_site: SameSite::Strict,
            session_lifetime: Duration::hours(2),
            secret_key: SecretString::new(""),
        }
    }
}

impl SessionConfig {
    /// Validates the configuration.
    ///
    /// Returns an error if the secret key is empty.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.secret_key.is_empty() {
            return Err("secret_key must not be empty");
        }
        if self.secret_key.len() < 32 {
            return Err("secret_key should be at least 32 bytes");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SessionConfig::default();
        assert_eq!(config.cookie_name, "enclave_session");
        assert_eq!(config.cookie_path, "/");
        assert!(config.cookie_secure);
        assert!(config.cookie_http_only);
        assert_eq!(config.cookie_same_site, SameSite::Strict);
    }

    #[test]
    fn test_validate_empty_secret() {
        let config = SessionConfig::default();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_short_secret() {
        let config = SessionConfig {
            secret_key: SecretString::new("short"),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_valid_secret() {
        let config = SessionConfig {
            secret_key: SecretString::new("this-is-a-very-long-secret-key-for-testing"),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }
}
