use axum::http::{Method, header};
use tower_http::cors::CorsLayer;

/// development only - allows all origins
pub fn permissive() -> CorsLayer {
    CorsLayer::permissive()
}

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
