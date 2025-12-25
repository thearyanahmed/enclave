use actix_web::{
    HttpMessage, HttpRequest, HttpResponse,
    body::EitherBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    http::header,
};
use futures::future::{LocalBoxFuture, Ready, ok};
use std::sync::Arc;
use std::task::{Context, Poll};

use super::limit::{KeyStrategy, Limit};
use super::store::RateLimitStore;

/// Throttle middleware for actix-web.
///
/// Applies rate limiting to requests based on the configured limit.
///
/// # Example
///
/// ```rust,ignore
/// use enclave::rate_limit::{RateLimiter, Limit, InMemoryStore};
/// use std::sync::Arc;
///
/// let store = Arc::new(InMemoryStore::new());
/// let limiter = RateLimiter::new(store)
///     .for_("api", Limit::per_minute(60));
///
/// App::new()
///     .wrap(limiter.throttle("api"))
///     .route("/api/resource", web::get().to(handler))
/// ```
#[derive(Clone)]
pub struct Throttle {
    store: Arc<dyn RateLimitStore>,
    limit: Option<Limit>,
    limit_name: String,
}

impl Throttle {
    /// Creates a new throttle middleware.
    #[must_use]
    pub fn new(store: Arc<dyn RateLimitStore>, limit: Option<Limit>, limit_name: String) -> Self {
        Self {
            store,
            limit,
            limit_name,
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for Throttle
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = actix_web::Error;
    type Transform = ThrottleMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(ThrottleMiddleware {
            service,
            store: Arc::clone(&self.store),
            limit: self.limit.clone(),
            limit_name: self.limit_name.clone(),
        })
    }
}

/// The actual middleware service.
pub struct ThrottleMiddleware<S> {
    service: S,
    store: Arc<dyn RateLimitStore>,
    limit: Option<Limit>,
    limit_name: String,
}

impl<S, B> Service<ServiceRequest> for ThrottleMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let Some(limit) = self.limit.clone() else {
            // No limit configured, pass through
            let fut = self.service.call(req);
            return Box::pin(async move {
                let res = fut.await?;
                Ok(res.map_into_left_body())
            });
        };

        let store = Arc::clone(&self.store);
        let limit_name = self.limit_name.clone();
        let key = extract_key(&req, &limit.key_strategy);

        let fut = self.service.call(req);

        Box::pin(async move {
            let full_key = format!("{limit_name}:{key}");
            let info = store.increment(&full_key, limit.window_secs()).await;

            match info {
                Ok(info) => {
                    if info.attempts > limit.max_attempts {
                        // Rate limited
                        let retry_after = info.available_in();
                        let message = limit
                            .get_message()
                            .unwrap_or("Too many requests. Please try again later.");

                        log::warn!(
                            target: "enclave_auth",
                            "msg=\"rate limited\", limit=\"{limit_name}\", retry_after={retry_after}"
                        );

                        let response = HttpResponse::TooManyRequests()
                            .insert_header((header::RETRY_AFTER, retry_after.to_string()))
                            .insert_header(("X-RateLimit-Limit", limit.max_attempts.to_string()))
                            .insert_header(("X-RateLimit-Remaining", "0"))
                            .insert_header((
                                "X-RateLimit-Reset",
                                info.reset_at.timestamp().to_string(),
                            ))
                            .json(serde_json::json!({
                                "error": message,
                                "code": "RATE_LIMITED",
                                "retry_after": retry_after
                            }));

                        Ok(ServiceResponse::new(
                            fut.await?.into_parts().0,
                            response.map_into_right_body(),
                        ))
                    } else {
                        // Allowed - add rate limit headers
                        let res = fut.await?;
                        let remaining = limit.max_attempts.saturating_sub(info.attempts);

                        let (req, mut response) = res.into_parts();
                        let headers = response.headers_mut();

                        headers.insert(
                            header::HeaderName::from_static("x-ratelimit-limit"),
                            header::HeaderValue::from_str(&limit.max_attempts.to_string())
                                .unwrap_or_else(|_| header::HeaderValue::from_static("0")),
                        );
                        headers.insert(
                            header::HeaderName::from_static("x-ratelimit-remaining"),
                            header::HeaderValue::from_str(&remaining.to_string())
                                .unwrap_or_else(|_| header::HeaderValue::from_static("0")),
                        );
                        headers.insert(
                            header::HeaderName::from_static("x-ratelimit-reset"),
                            header::HeaderValue::from_str(&info.reset_at.timestamp().to_string())
                                .unwrap_or_else(|_| header::HeaderValue::from_static("0")),
                        );

                        Ok(ServiceResponse::new(req, response).map_into_left_body())
                    }
                }
                Err(e) => {
                    // Store error - let request through but log
                    log::error!(
                        target: "enclave_auth",
                        "msg=\"rate limit store error\", limit=\"{limit_name}\", error=\"{e}\""
                    );

                    let res = fut.await?;
                    Ok(res.map_into_left_body())
                }
            }
        })
    }
}

/// Extracts the rate limit key from the request based on the strategy.
fn extract_key(req: &ServiceRequest, strategy: &KeyStrategy) -> String {
    match strategy {
        KeyStrategy::Ip => extract_client_ip(req.request()),
        KeyStrategy::User => {
            // Try to get user ID from request extensions or fall back to IP
            // This would need to be set by an auth middleware
            req.request()
                .extensions()
                .get::<UserId>()
                .map_or_else(|| extract_client_ip(req.request()), |id| id.0.to_string())
        }
        KeyStrategy::Global => "global".to_owned(),
        KeyStrategy::Custom(f) => {
            f(req.request()).unwrap_or_else(|| extract_client_ip(req.request()))
        }
    }
}

/// User ID extension for user-based rate limiting.
#[derive(Debug, Clone)]
pub struct UserId(pub i32);

/// Extracts the client IP from a request.
///
/// Checks common proxy headers first, then falls back to peer address.
pub fn extract_client_ip(req: &HttpRequest) -> String {
    // Check X-Forwarded-For (may contain multiple IPs)
    if let Some(xff) = req.headers().get("X-Forwarded-For") {
        if let Ok(xff_str) = xff.to_str() {
            if let Some(first_ip) = xff_str.split(',').next() {
                return first_ip.trim().to_owned();
            }
        }
    }

    // Check X-Real-IP
    if let Some(real_ip) = req.headers().get("X-Real-IP") {
        if let Ok(ip) = real_ip.to_str() {
            return ip.trim().to_owned();
        }
    }

    // Check CF-Connecting-IP (Cloudflare)
    if let Some(cf_ip) = req.headers().get("CF-Connecting-IP") {
        if let Ok(ip) = cf_ip.to_str() {
            return ip.trim().to_owned();
        }
    }

    // Fall back to peer address
    req.peer_addr()
        .map_or_else(|| "unknown".to_owned(), |addr| addr.ip().to_string())
}
