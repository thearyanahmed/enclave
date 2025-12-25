use chrono::Duration;
use std::fmt;

use crate::AuthError;

/// Minimum required length for JWT secret in bytes.
pub const MIN_SECRET_LENGTH: usize = 32;

/// Configuration for JWT token generation and validation.
#[derive(Clone)]
pub struct JwtConfig {
    /// Secret key used for signing tokens (HS256).
    pub(crate) secret: String,
    /// Access token expiry duration. Default: 15 minutes.
    pub(crate) access_expiry: Duration,
    /// Refresh token expiry duration. Default: 7 days.
    pub(crate) refresh_expiry: Duration,
    /// Issuer claim (optional).
    pub(crate) issuer: Option<String>,
    /// Audience claim (optional).
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
    /// Creates a new JWT configuration with the given secret.
    ///
    /// # Arguments
    /// * `secret` - The secret key for signing tokens. Must be at least 32 bytes.
    ///
    /// # Errors
    /// Returns `AuthError::ConfigurationError` if the secret is less than 32 bytes.
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

    /// Sets the access token expiry duration.
    #[must_use]
    pub fn with_access_expiry(mut self, expiry: Duration) -> Self {
        self.access_expiry = expiry;
        self
    }

    /// Sets the refresh token expiry duration.
    #[must_use]
    pub fn with_refresh_expiry(mut self, expiry: Duration) -> Self {
        self.refresh_expiry = expiry;
        self
    }

    /// Sets the token expiry duration (alias for `with_access_expiry`).
    #[must_use]
    pub fn with_expiry(mut self, expiry: Duration) -> Self {
        self.access_expiry = expiry;
        self
    }

    /// Sets the issuer claim.
    #[must_use]
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Sets the audience claim.
    #[must_use]
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Returns the configured access token expiry duration.
    pub fn expiry(&self) -> Duration {
        self.access_expiry
    }

    /// Returns the configured access token expiry duration.
    pub fn access_expiry(&self) -> Duration {
        self.access_expiry
    }

    /// Returns the configured refresh token expiry duration.
    pub fn refresh_expiry(&self) -> Duration {
        self.refresh_expiry
    }
}
