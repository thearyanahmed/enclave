//! Event system for authentication actions.
//!
//! Events are automatically fired from all authentication actions. If no
//! listeners are registered, they are silently ignored (zero overhead).
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use enclave::register_event_listeners;
//! use enclave::events::listeners::LoggingListener;
//!
//! fn main() {
//!     // register listeners at startup
//!     register_event_listeners(|registry| {
//!         registry.listen(LoggingListener::new());
//!     });
//!
//!     // events will now be logged
//! }
//! ```
//!
//! # Custom Listeners
//!
//! Implement the [`Listener`] trait to create custom event handlers:
//!
//! ```rust,ignore
//! use enclave::events::{AuthEvent, Listener};
//! use async_trait::async_trait;
//!
//! struct MetricsListener;
//!
//! #[async_trait]
//! impl Listener for MetricsListener {
//!     async fn handle(&self, event: &AuthEvent) {
//!         match event {
//!             AuthEvent::LoginSuccess { .. } => {
//!                 // increment login success counter
//!             }
//!             AuthEvent::LoginFailed { .. } => {
//!                 // increment login failure counter
//!             }
//!             _ => {}
//!         }
//!     }
//! }
//! ```

mod event;
mod listener;
mod registry;

pub mod listeners;

pub use event::AuthEvent;
pub use listener::Listener;
pub use registry::{dispatch, register_event_listeners};
