mod limit;
mod limiter;
mod store;

#[cfg(feature = "actix")]
mod middleware;

#[cfg(feature = "sqlx_postgres")]
mod postgres_store;

pub use limit::Limit;
pub use limiter::{RateLimitResult, RateLimiter};
#[cfg(feature = "actix")]
pub use middleware::{Throttle, UserId, extract_client_ip};
#[cfg(feature = "sqlx_postgres")]
pub use postgres_store::PostgresRateLimitStore;
pub use store::{InMemoryStore, RateLimitInfo, RateLimitStore};
