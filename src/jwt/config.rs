use chrono::Duration;

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

impl JwtConfig {
    /// Creates a new JWT configuration with the given secret.
    ///
    /// # Arguments
    /// * `secret` - The secret key for signing tokens. Should be at least 32 bytes.
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
            access_expiry: Duration::minutes(15),
            refresh_expiry: Duration::days(7),
            issuer: None,
            audience: None,
        }
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
