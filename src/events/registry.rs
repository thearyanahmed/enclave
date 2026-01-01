use std::sync::OnceLock;

use super::{AuthEvent, Listener};

static REGISTRY: OnceLock<EventRegistry> = OnceLock::new();

/// Registry holding all registered event listeners.
///
/// Use [`register_event_listeners`] to configure listeners at application startup.
pub struct EventRegistry {
    listeners: Vec<Box<dyn Listener>>,
}

impl EventRegistry {
    fn new() -> Self {
        Self {
            listeners: Vec::new(),
        }
    }

    /// Register a listener to receive events.
    ///
    /// Listeners are called in the order they are registered.
    pub fn listen(&mut self, listener: impl Listener) -> &mut Self {
        self.listeners.push(Box::new(listener));
        self
    }

    async fn dispatch(&self, event: &AuthEvent) {
        for listener in &self.listeners {
            listener.handle(event).await;
        }
    }
}

/// Register event listeners at application startup.
///
/// Call this once during initialization to configure which listeners
/// should handle authentication events. If not called, events are
/// silently ignored.
///
/// # Example
///
/// ```rust,ignore
/// use enclave::register_event_listeners;
/// use enclave::events::listeners::LoggingListener;
///
/// fn main() {
///     register_event_listeners(|registry| {
///         registry
///             .listen(LoggingListener::new())
///             .listen(MyCustomListener::new());
///     });
///
///     // start server...
/// }
/// ```
///
/// # Panics
///
/// Does not panic, but logs a warning if called more than once.
/// Only the first call takes effect.
pub fn register_event_listeners<F>(f: F)
where
    F: FnOnce(&mut EventRegistry),
{
    let mut registry = EventRegistry::new();
    f(&mut registry);
    if REGISTRY.set(registry).is_err() {
        log::warn!(
            target: "enclave",
            "register_event_listeners called more than once, ignoring"
        );
    }
}

/// Dispatch an event to all registered listeners.
///
/// If no listeners are registered, this is a no-op.
pub async fn dispatch(event: AuthEvent) {
    if let Some(registry) = REGISTRY.get() {
        registry.dispatch(&event).await;
    }
}
