use async_trait::async_trait;

use crate::events::{AuthEvent, Listener};

/// Emits authentication events as tracing spans/events.
///
/// Requires the `tracing` feature to be enabled.
///
/// # Example
///
/// ```rust,ignore
/// use enclave::register_event_listeners;
/// use enclave::events::listeners::TracingListener;
///
/// register_event_listeners(|registry| {
///     registry.listen(TracingListener);
/// });
/// ```
pub struct TracingListener;

#[async_trait]
impl Listener for TracingListener {
    async fn handle(&self, event: &AuthEvent) {
        tracing::info!(
            target: "enclave::events",
            event_name = event.name(),
            ?event,
            "auth event"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[tokio::test]
    async fn test_tracing_listener_handle() {
        let listener = TracingListener;
        let event = AuthEvent::LoginSuccess {
            user_id: 1,
            email: "test@example.com".to_owned(),
            at: Utc::now(),
        };

        // should not panic
        listener.handle(&event).await;
    }
}
