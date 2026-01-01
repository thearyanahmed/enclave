//! Built-in event listeners.
//!
//! These listeners provide common functionality out of the box.
//! Use them with [`register_event_listeners`](crate::register_event_listeners).

mod logging;
#[cfg(feature = "tracing")]
mod tracing;

pub use logging::LoggingListener;
#[cfg(feature = "tracing")]
pub use self::tracing::TracingListener;
