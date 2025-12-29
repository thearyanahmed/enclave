#[cfg(feature = "actix")]
use std::sync::Arc;

#[cfg(feature = "actix")]
use actix_web::HttpRequest;
use chrono::Duration;

/// Type alias for custom key extraction functions.
#[cfg(feature = "actix")]
pub type KeyExtractor = Arc<dyn Fn(&HttpRequest) -> Option<String> + Send + Sync>;

#[derive(Clone)]
pub enum KeyStrategy {
    Ip,
    User,
    Global,
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

#[derive(Debug, Clone)]
pub struct Limit {
    pub(crate) max_attempts: u32,
    pub(crate) window: Duration,
    pub(crate) key_strategy: KeyStrategy,
    pub(crate) message: Option<String>,
}

impl Limit {
    #[must_use]
    pub fn new(max_attempts: u32, window: Duration) -> Self {
        Self {
            max_attempts,
            window,
            key_strategy: KeyStrategy::Ip,
            message: None,
        }
    }

    #[must_use]
    pub fn per_second(max_attempts: u32) -> Self {
        Self::new(max_attempts, Duration::seconds(1))
    }

    #[must_use]
    pub fn per_minute(max_attempts: u32) -> Self {
        Self::new(max_attempts, Duration::minutes(1))
    }

    #[must_use]
    pub fn per_hour(max_attempts: u32) -> Self {
        Self::new(max_attempts, Duration::hours(1))
    }

    #[must_use]
    pub fn per_day(max_attempts: u32) -> Self {
        Self::new(max_attempts, Duration::days(1))
    }

    #[must_use]
    pub fn by_ip(mut self) -> Self {
        self.key_strategy = KeyStrategy::Ip;
        self
    }

    /// unauthenticated requests fall back to IP-based limiting
    #[must_use]
    pub fn by_user(mut self) -> Self {
        self.key_strategy = KeyStrategy::User;
        self
    }

    #[must_use]
    pub fn globally(mut self) -> Self {
        self.key_strategy = KeyStrategy::Global;
        self
    }

    #[cfg(feature = "actix")]
    #[must_use]
    pub fn by<F>(mut self, key_fn: F) -> Self
    where
        F: Fn(&HttpRequest) -> Option<String> + Send + Sync + 'static,
    {
        self.key_strategy = KeyStrategy::Custom(Arc::new(key_fn));
        self
    }

    #[must_use]
    pub fn message(mut self, msg: impl Into<String>) -> Self {
        self.message = Some(msg.into());
        self
    }

    pub fn window_secs(&self) -> u64 {
        u64::try_from(self.window.num_seconds()).unwrap_or(u64::MAX)
    }

    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

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
