use chrono::Duration;

/// Configuration for JWT token generation and validation.
#[derive(Clone)]
pub struct JwtConfig {
    /// Secret key used for signing tokens (HS256).
    pub(crate) secret: String,
    /// Token expiry duration. Default: 1 hour.
    pub(crate) expiry: Duration,
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
            expiry: Duration::hours(1),
            issuer: None,
            audience: None,
        }
    }

    /// Sets the token expiry duration.
    #[must_use]
    pub fn with_expiry(mut self, expiry: Duration) -> Self {
        self.expiry = expiry;
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

    /// Returns the configured expiry duration.
    pub fn expiry(&self) -> Duration {
        self.expiry
    }
}
