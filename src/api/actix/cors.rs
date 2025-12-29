use actix_cors::Cors;
use actix_web::http::{Method, header};

/// development only - allows all origins
pub fn permissive() -> Cors {
    Cors::permissive()
}

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
