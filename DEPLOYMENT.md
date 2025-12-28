# Deployment Guide

> **WORK IN PROGRESS**: This deployment guide is under active development. Some sections may be incomplete or subject to change.

This guide covers deploying an application using Enclave to production.

## Prerequisites

- PostgreSQL 13+ (or compatible database)
- Rust 1.75+ (for building)
- HTTPS-enabled load balancer or reverse proxy

## Environment Variables

```bash
# Required
DATABASE_URL=postgres://user:password@host:5432/dbname?sslmode=require
JWT_SECRET=<32+ byte random secret>

# Optional
RUST_LOG=info,enclave=debug
PORT=8080
```

### Generating a JWT Secret

```bash
# Linux/macOS
openssl rand -base64 32

# Output example: K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=
```

Store this securely. Never commit to version control.

## Database Setup

### 1. Run Migrations

```bash
# Using sqlx-cli
sqlx migrate run

# Or execute migration files directly (for PostgreSQL)
psql $DATABASE_URL -f migrations/postgres/core/*.sql
psql $DATABASE_URL -f migrations/postgres/rate_limit/*.sql  # if using rate_limit feature
```

### 2. Verify Tables

```sql
SELECT table_name FROM information_schema.tables
WHERE table_schema = 'public'
ORDER BY table_name;
```

Expected tables:

- `users`
- `access_tokens`
- `password_reset_tokens`
- `email_verification_tokens`
- `login_attempts`
- `magic_link_tokens` (if magic_link feature enabled)
- `audit_logs` (if audit_log feature enabled)

### 3. Create Indexes (Optional)

The migrations create essential indexes. For high-traffic deployments:

```sql
-- Additional indexes for large tables
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_access_tokens_expires
  ON access_tokens(expires_at) WHERE expires_at < NOW();

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_login_attempts_cleanup
  ON login_attempts(attempted_at) WHERE attempted_at < NOW() - INTERVAL '1 day';
```

## Production Configuration

### Password Hasher

Use production-grade Argon2 settings:

```rust
use enclave::Argon2Hasher;

// OWASP 2024 recommended: 64 MiB memory, 3 iterations, 4 threads
let hasher = Argon2Hasher::production();
```

### Auth Configuration

```rust
use enclave::config::{AuthConfig, TokenConfig, RateLimitConfig};
use chrono::Duration;

let config = AuthConfig {
    tokens: TokenConfig {
        access_token_expiry: Duration::hours(1),
        password_reset_expiry: Duration::minutes(15),
        email_verification_expiry: Duration::hours(24),
        ..Default::default()
    },
    rate_limit: RateLimitConfig {
        max_failed_attempts: 5,
        lockout_duration: Duration::minutes(15),
    },
    ..Default::default()
};
```

### JWT Configuration

```rust
use enclave::jwt::{JwtConfig, JwtService};

let config = JwtConfig::new(std::env::var("JWT_SECRET")?)
    .with_access_expiry(Duration::minutes(15))
    .with_refresh_expiry(Duration::days(7))
    .with_issuer("your-app-name");

let jwt_service = JwtService::new(config);
```

## Token Cleanup

Expired tokens accumulate in the database. Run cleanup periodically.

### Using PruneExpiredTokensAction

```rust
use enclave::actions::PruneExpiredTokensAction;

let action = PruneExpiredTokensAction::new(
    token_repo.clone(),
    password_reset_repo.clone(),
    email_verification_repo.clone(),
);

let result = action.execute().await?;
println!("Pruned {} total tokens", result.total());
```

### Cron Job (Recommended)

```bash
# Run every hour
0 * * * * /path/to/your-app --prune-tokens >> /var/log/token-cleanup.log 2>&1
```

Or use PostgreSQL's `pg_cron`:

```sql
SELECT cron.schedule('prune-tokens', '0 * * * *', $$
  DELETE FROM access_tokens WHERE expires_at < NOW();
  DELETE FROM password_reset_tokens WHERE expires_at < NOW();
  DELETE FROM email_verification_tokens WHERE expires_at < NOW();
  DELETE FROM magic_link_tokens WHERE expires_at < NOW();
  DELETE FROM login_attempts WHERE attempted_at < NOW() - INTERVAL '1 day';
$$);
```

## Connection Pooling

Configure appropriate pool sizes:

```rust
use sqlx::postgres::PgPoolOptions;

let pool = PgPoolOptions::new()
    .max_connections(20)        // Adjust based on workload
    .min_connections(5)
    .acquire_timeout(Duration::from_secs(3))
    .idle_timeout(Duration::from_secs(600))
    .connect(&database_url)
    .await?;
```

**Sizing guideline**: max_connections = (number of app instances \* connections per instance) < PostgreSQL max_connections

## Logging

Enable tracing for production monitoring:

```rust
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

tracing_subscriber::registry()
    .with(EnvFilter::from_default_env())
    .with(tracing_subscriber::fmt::layer().json())
    .init();
```

Set log levels via `RUST_LOG`:

```bash
# Recommended production settings
RUST_LOG=warn,enclave=info,your_app=info
```

## Health Checks

Implement a health endpoint:

```rust
use actix_web::{get, HttpResponse};

#[get("/health")]
async fn health(pool: web::Data<PgPool>) -> HttpResponse {
    match sqlx::query("SELECT 1").fetch_one(pool.get_ref()).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "healthy"})),
        Err(_) => HttpResponse::ServiceUnavailable().json(serde_json::json!({"status": "unhealthy"})),
    }
}
```

## Reverse Proxy Configuration

### Nginx Example

```nginx
upstream app {
    server 127.0.0.1:8080;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name api.example.com;

    ssl_certificate /etc/letsencrypt/live/api.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.example.com/privkey.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;

    location / {
        proxy_pass http://app;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";

        # Timeouts
        proxy_connect_timeout 10s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }

    # Rate limiting at proxy level
    limit_req_zone $binary_remote_addr zone=auth:10m rate=10r/s;

    location /auth/ {
        limit_req zone=auth burst=20 nodelay;
        proxy_pass http://app;
        # ... same proxy settings
    }
}
```

## Docker Deployment

### Dockerfile

```dockerfile
FROM rust:1.83-alpine AS builder

WORKDIR /app
COPY . .
RUN apk add --no-cache musl-dev openssl-dev
RUN cargo build --release --features "actix sqlx_postgres tracing"

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/target/release/your-app /usr/local/bin/
EXPOSE 8080
CMD ["your-app"]
```

### Docker Compose

```yaml
version: "3.8"

services:
  app:
    build: .
    ports:
      - "8080:8080"
    environment:
      DATABASE_URL: postgres://enclave:enclave@db:5432/enclave
      JWT_SECRET: ${JWT_SECRET}
      RUST_LOG: info,enclave=debug
    depends_on:
      db:
        condition: service_healthy
    restart: unless-stopped

  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: enclave
      POSTGRES_PASSWORD: enclave
      POSTGRES_DB: enclave
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U enclave"]
      interval: 5s
      timeout: 5s
      retries: 5

volumes:
  pgdata:
```

## Scaling Considerations

### Horizontal Scaling

Enclave is stateless-friendly:

- **JWT mode**: Fully stateless, scale horizontally without constraints
- **Stateful tokens**: All instances share the same database

### Database Considerations

1. **Read replicas**: Route read-heavy queries (token validation) to replicas
2. **Connection pooling**: Use PgBouncer for connection management at scale
3. **Partitioning**: Consider partitioning `login_attempts` by date for cleanup efficiency

### Caching

Token validation can be cached:

```rust
// Example with Redis (implement TokenRepository)
async fn find_token(&self, token: &str) -> Result<Option<AccessToken>, AuthError> {
    // Check cache first
    if let Some(cached) = self.redis.get(&cache_key).await? {
        return Ok(Some(cached));
    }

    // Fall back to database
    let result = self.postgres.find_token(token).await?;

    // Cache for short duration (don't cache longer than token TTL)
    if let Some(ref token) = result {
        self.redis.set(&cache_key, token, Duration::minutes(5)).await?;
    }

    Ok(result)
}
```

## Monitoring Checklist

- [ ] Health check endpoint responding
- [ ] Database connection pool healthy
- [ ] Login failure rate within normal bounds
- [ ] Token cleanup running on schedule
- [ ] No expired token buildup in database
- [ ] Memory usage stable (no leaks)
- [ ] Response times within SLA

## Troubleshooting

### High Login Latency

1. Check Argon2 parameters (production preset uses 64 MiB)
2. Verify database indexes on `users.email`
3. Monitor connection pool exhaustion

### Token Table Growth

Run cleanup more frequently:

```bash
# Check table sizes
SELECT relname, pg_size_pretty(pg_total_relation_size(relid))
FROM pg_catalog.pg_statio_user_tables
ORDER BY pg_total_relation_size(relid) DESC;
```

### Rate Limit Bypass

Ensure `X-Real-IP` or `X-Forwarded-For` is set correctly by your reverse proxy. Enclave uses the IP for rate limiting when configured.
