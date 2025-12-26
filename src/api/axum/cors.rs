//! CORS configuration for Axum using tower-http.

use axum::http::{Method, header};
use tower_http::cors::CorsLayer;

/// Creates a permissive CORS configuration that allows all origins.
///
/// **Warning**: This is intended for development only. Do not use in production.
///
/// Allows:
/// - Any origin
/// - Any method
/// - Any header
pub fn permissive() -> CorsLayer {
    CorsLayer::permissive()
}

/// Creates a default CORS configuration suitable for authentication APIs.
///
/// Allows:
/// - Specified origins only
/// - Common HTTP methods (GET, POST, PUT, DELETE, OPTIONS)
/// - Common headers (Authorization, Content-Type, Accept)
/// - Credentials (cookies, authorization headers)
/// - Max age of 1 hour for preflight caching
///
/// # Arguments
/// * `allowed_origins` - List of allowed origin URLs (e.g., `["https://example.com"]`)
pub fn default(allowed_origins: &[&str]) -> CorsLayer {
    let origins: Vec<_> = allowed_origins
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT])
        .allow_credentials(true)
        .max_age(std::time::Duration::from_secs(3600))
}

/// Creates a restrictive CORS configuration with custom settings.
///
/// This is a builder-style function for more control over CORS settings.
///
/// # Arguments
/// * `allowed_origins` - List of allowed origin URLs
/// * `allowed_methods` - List of allowed HTTP methods
/// * `allowed_headers` - List of allowed headers
/// * `allow_credentials` - Whether to allow credentials
pub fn custom(
    allowed_origins: &[&str],
    allowed_methods: Vec<Method>,
    allowed_headers: Vec<header::HeaderName>,
    allow_credentials: bool,
) -> CorsLayer {
    let origins: Vec<_> = allowed_origins
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    let mut cors = CorsLayer::new()
        .allow_origin(origins)
        .allow_methods(allowed_methods)
        .allow_headers(allowed_headers)
        .max_age(std::time::Duration::from_secs(3600));

    if allow_credentials {
        cors = cors.allow_credentials(true);
    }

    cors
}
