use chrono::Duration;

use crate::SecretString;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SameSite {
    None,
    Lax,
    #[default]
    Strict,
}

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub cookie_name: String,
    pub cookie_path: String,
    pub cookie_domain: Option<String>,
    pub cookie_secure: bool,
    pub cookie_http_only: bool,
    pub cookie_same_site: SameSite,
    pub session_lifetime: Duration,
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
