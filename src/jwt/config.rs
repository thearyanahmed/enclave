use std::fmt;

use chrono::Duration;

use crate::AuthError;

/// Minimum required length for JWT secret in bytes.
pub const MIN_SECRET_LENGTH: usize = 32;

#[derive(Clone)]
pub struct JwtConfig {
    pub(crate) secret: String,
    pub(crate) access_expiry: Duration,
    pub(crate) refresh_expiry: Duration,
    pub(crate) issuer: Option<String>,
    pub(crate) audience: Option<String>,
}

impl fmt::Debug for JwtConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtConfig")
            .field("secret", &"[REDACTED]")
            .field("access_expiry", &self.access_expiry)
            .field("refresh_expiry", &self.refresh_expiry)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .finish()
    }
}

impl JwtConfig {
    /// secret must be at least 32 bytes
    pub fn new(secret: impl Into<String>) -> Result<Self, AuthError> {
        let secret = secret.into();

        if secret.len() < MIN_SECRET_LENGTH {
            return Err(AuthError::ConfigurationError(format!(
                "JWT secret must be at least {MIN_SECRET_LENGTH} bytes, got {}",
                secret.len()
            )));
        }

        Ok(Self {
            secret,
            access_expiry: Duration::minutes(15),
            refresh_expiry: Duration::days(7),
            issuer: None,
            audience: None,
        })
    }

    #[must_use]
    pub fn with_access_expiry(mut self, expiry: Duration) -> Self {
        self.access_expiry = expiry;
        self
    }

    #[must_use]
    pub fn with_refresh_expiry(mut self, expiry: Duration) -> Self {
        self.refresh_expiry = expiry;
        self
    }

    /// alias for `with_access_expiry`
    #[must_use]
    pub fn with_expiry(mut self, expiry: Duration) -> Self {
        self.access_expiry = expiry;
        self
    }

    #[must_use]
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    #[must_use]
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    pub fn expiry(&self) -> Duration {
        self.access_expiry
    }

    pub fn access_expiry(&self) -> Duration {
        self.access_expiry
    }

    pub fn refresh_expiry(&self) -> Duration {
        self.refresh_expiry
    }
}
