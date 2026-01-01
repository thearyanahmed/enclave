use async_trait::async_trait;

use super::AuthEvent;

/// Trait for handling authentication events asynchronously.
///
/// Implement this trait to create custom event listeners. Listeners can
/// perform any async operation: logging, sending notifications, updating
/// metrics, etc.
///
/// # Example
///
/// ```rust,ignore
/// use enclave::events::{AuthEvent, Listener};
/// use async_trait::async_trait;
///
/// struct SlackAlertListener {
///     webhook_url: String,
/// }
///
/// #[async_trait]
/// impl Listener for SlackAlertListener {
///     async fn handle(&self, event: &AuthEvent) {
///         if let AuthEvent::LoginFailed { email, reason, .. } = event {
///             // send alert to slack
///         }
///     }
/// }
/// ```
#[async_trait]
pub trait Listener: Send + Sync + 'static {
    /// Handle an authentication event.
    ///
    /// This method is called for every event dispatched. Filter by matching
    /// on the event variant to handle specific events.
    async fn handle(&self, event: &AuthEvent);
}
