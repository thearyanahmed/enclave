use chrono::Duration;

#[cfg(feature = "actix")]
use actix_web::HttpRequest;
#[cfg(feature = "actix")]
use std::sync::Arc;

/// Type alias for custom key extraction functions.
#[cfg(feature = "actix")]
pub type KeyExtractor = Arc<dyn Fn(&HttpRequest) -> Option<String> + Send + Sync>;

/// Key extraction strategy for rate limiting.
#[derive(Clone)]
pub enum KeyStrategy {
    /// Rate limit by client IP address.
    Ip,
    /// Rate limit by authenticated user ID.
    User,
    /// Rate limit globally (same key for all requests).
    Global,
    /// Custom key extraction function.
    #[cfg(feature = "actix")]
    Custom(KeyExtractor),
}

impl std::fmt::Debug for KeyStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip => write!(f, "Ip"),
            Self::User => write!(f, "User"),
            Self::Global => write!(f, "Global"),
            #[cfg(feature = "actix")]
            Self::Custom(_) => write!(f, "Custom(...)"),
        }
    }
}

/// A rate limit definition.
///
/// Defines the maximum number of attempts allowed within a time window.
///
/// # Examples
///
/// ```rust
/// use enclave::rate_limit::Limit;
///
/// // 60 requests per minute
/// let limit = Limit::per_minute(60);
///
/// // 5 login attempts per minute, keyed by IP
/// let login_limit = Limit::per_minute(5).by_ip();
///
/// // 1000 requests per hour, keyed by user
/// let api_limit = Limit::per_hour(1000).by_user();
///
/// // Custom: 10 requests per 30 seconds
/// let custom = Limit::new(10, chrono::Duration::seconds(30));
/// ```
#[derive(Debug, Clone)]
pub struct Limit {
    /// Maximum number of attempts allowed.
    pub(crate) max_attempts: u32,
    /// Time window for the rate limit.
    pub(crate) window: Duration,
    /// Strategy for extracting the rate limit key.
    pub(crate) key_strategy: KeyStrategy,
    /// Custom response message when rate limited.
    pub(crate) message: Option<String>,
}

impl Limit {
    /// Creates a new rate limit with the specified max attempts and window.
    #[must_use]
    pub fn new(max_attempts: u32, window: Duration) -> Self {
        Self {
            max_attempts,
            window,
            key_strategy: KeyStrategy::Ip,
            message: None,
        }
    }

    /// Creates a rate limit of N requests per second.
    #[must_use]
    pub fn per_second(max_attempts: u32) -> Self {
        Self::new(max_attempts, Duration::seconds(1))
    }

    /// Creates a rate limit of N requests per minute.
    #[must_use]
    pub fn per_minute(max_attempts: u32) -> Self {
        Self::new(max_attempts, Duration::minutes(1))
    }

    /// Creates a rate limit of N requests per hour.
    #[must_use]
    pub fn per_hour(max_attempts: u32) -> Self {
        Self::new(max_attempts, Duration::hours(1))
    }

    /// Creates a rate limit of N requests per day.
    #[must_use]
    pub fn per_day(max_attempts: u32) -> Self {
        Self::new(max_attempts, Duration::days(1))
    }

    /// Sets the key strategy to IP-based (default).
    #[must_use]
    pub fn by_ip(mut self) -> Self {
        self.key_strategy = KeyStrategy::Ip;
        self
    }

    /// Sets the key strategy to user-based.
    ///
    /// Requires the user to be authenticated. Unauthenticated requests
    /// will fall back to IP-based limiting.
    #[must_use]
    pub fn by_user(mut self) -> Self {
        self.key_strategy = KeyStrategy::User;
        self
    }

    /// Sets the key strategy to global (single bucket for all requests).
    #[must_use]
    pub fn globally(mut self) -> Self {
        self.key_strategy = KeyStrategy::Global;
        self
    }

    /// Sets a custom key extraction function.
    #[cfg(feature = "actix")]
    #[must_use]
    pub fn by<F>(mut self, key_fn: F) -> Self
    where
        F: Fn(&HttpRequest) -> Option<String> + Send + Sync + 'static,
    {
        self.key_strategy = KeyStrategy::Custom(Arc::new(key_fn));
        self
    }

    /// Sets a custom message to return when rate limited.
    #[must_use]
    pub fn message(mut self, msg: impl Into<String>) -> Self {
        self.message = Some(msg.into());
        self
    }

    /// Returns the window duration in seconds.
    pub fn window_secs(&self) -> u64 {
        u64::try_from(self.window.num_seconds()).unwrap_or(u64::MAX)
    }

    /// Returns the max attempts.
    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    /// Returns the custom message, if set.
    pub fn get_message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_limit_per_minute() {
        let limit = Limit::per_minute(60);
        assert_eq!(limit.max_attempts, 60);
        assert_eq!(limit.window_secs(), 60);
    }

    #[test]
    fn test_limit_per_hour() {
        let limit = Limit::per_hour(1000);
        assert_eq!(limit.max_attempts, 1000);
        assert_eq!(limit.window_secs(), 3600);
    }

    #[test]
    fn test_limit_builder() {
        let limit = Limit::per_minute(5)
            .by_ip()
            .message("Too many login attempts");

        assert_eq!(limit.max_attempts, 5);
        assert!(matches!(limit.key_strategy, KeyStrategy::Ip));
        assert_eq!(limit.get_message(), Some("Too many login attempts"));
    }
}
