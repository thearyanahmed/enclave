/// Configuration for tracing instrumentation on actions.
#[derive(Debug, Clone)]
pub struct TracingConfig {
    /// Span name for the traced action.
    pub span_name: &'static str,
}

impl TracingConfig {
    /// Creates a new TracingConfig with a custom span name.
    pub fn new(span_name: &'static str) -> Self {
        Self { span_name }
    }

    /// Creates a TracingConfig with a default span name.
    pub fn default_span() -> Self {
        Self { span_name: "action" }
    }
}
