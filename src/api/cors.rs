use actix_cors::Cors;
use actix_web::http::{header, Method};

/// CORS configuration helpers for authentication APIs.
///
/// This module provides convenient CORS configurations for common use cases.
/// All functions return `actix_cors::Cors` which can be used with `.wrap()`.
///
/// # Example
/// ```ignore
/// use actix_web::App;
/// use enclave::api::cors;
///
/// // Development: allow all origins
/// App::new()
///     .wrap(cors::permissive())
///     .configure(configure::<...>);
///
/// // Production: specify allowed origins
/// App::new()
///     .wrap(cors::default(&["https://example.com"]))
///     .configure(configure::<...>);
/// ```

/// Creates a permissive CORS configuration that allows all origins.
///
/// **Warning**: This is intended for development only. Do not use in production.
///
/// Allows:
/// - Any origin
/// - Any method
/// - Any header
/// - Credentials
pub fn permissive() -> Cors {
    Cors::permissive()
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
pub fn default(allowed_origins: &[&str]) -> Cors {
    let mut cors = Cors::default()
        .allowed_methods(vec![
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allowed_headers(vec![
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
        ])
        .supports_credentials()
        .max_age(3600);

    for origin in allowed_origins {
        cors = cors.allowed_origin(origin);
    }

    cors
}

/// Creates a restrictive CORS configuration with custom settings.
///
/// This is a builder-style function for more control over CORS settings.
///
/// # Arguments
/// * `allowed_origins` - List of allowed origin URLs
/// * `allowed_methods` - List of allowed HTTP methods
/// * `allowed_headers` - List of allowed headers
/// * `supports_credentials` - Whether to allow credentials
pub fn custom(
    allowed_origins: &[&str],
    allowed_methods: Vec<Method>,
    allowed_headers: Vec<header::HeaderName>,
    supports_credentials: bool,
) -> Cors {
    let mut cors = Cors::default()
        .allowed_methods(allowed_methods)
        .allowed_headers(allowed_headers)
        .max_age(3600);

    for origin in allowed_origins {
        cors = cors.allowed_origin(origin);
    }

    if supports_credentials {
        cors = cors.supports_credentials();
    }

    cors
}
