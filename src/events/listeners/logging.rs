use async_trait::async_trait;

use crate::events::{AuthEvent, Listener};

/// Logs all authentication events using the `log` crate.
///
/// # Example
///
/// ```rust,ignore
/// use enclave::register_event_listeners;
/// use enclave::events::listeners::LoggingListener;
///
/// register_event_listeners(|registry| {
///     registry.listen(LoggingListener::new());
/// });
/// ```
pub struct LoggingListener {
    level: log::Level,
}

impl LoggingListener {
    /// Creates a new logging listener at INFO level.
    pub fn new() -> Self {
        Self {
            level: log::Level::Info,
        }
    }

    /// Creates a new logging listener at the specified level.
    pub fn with_level(level: log::Level) -> Self {
        Self { level }
    }
}

impl Default for LoggingListener {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Listener for LoggingListener {
    async fn handle(&self, event: &AuthEvent) {
        log::log!(
            target: "enclave::events",
            self.level,
            "event={} {:?}",
            event.name(),
            event
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_logging_listener_new() {
        let listener = LoggingListener::new();
        assert_eq!(listener.level, log::Level::Info);
    }

    #[test]
    fn test_logging_listener_default() {
        let listener = LoggingListener::default();
        assert_eq!(listener.level, log::Level::Info);
    }

    #[test]
    fn test_logging_listener_with_level() {
        let listener = LoggingListener::with_level(log::Level::Debug);
        assert_eq!(listener.level, log::Level::Debug);

        let listener = LoggingListener::with_level(log::Level::Warn);
        assert_eq!(listener.level, log::Level::Warn);
    }

    #[tokio::test]
    async fn test_logging_listener_handle() {
        let listener = LoggingListener::new();
        let event = AuthEvent::LoginSuccess {
            user_id: 1,
            email: "test@example.com".to_owned(),
            at: Utc::now(),
        };

        // should not panic
        listener.handle(&event).await;
    }
}
