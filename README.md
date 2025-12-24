# Enclave

Authentication library for Rust applications.

## Overview

Enclave provides the building blocks for user authentication: password hashing, token management, rate limiting, and optional HTTP/database integrations. It uses a trait-based architecture allowing custom storage backends.

## Installation

```toml
[dependencies]
enclave = "0.1"
```

With features:

```toml
[dependencies]
enclave = { version = "0.1", features = ["actix", "sqlx_postgres"] }
```

## Feature Flags

| Feature         | Description                            | Dependencies          |
| --------------- | -------------------------------------- | --------------------- |
| `actix`         | HTTP handlers and routes for actix-web | actix-web, actix-cors |
| `sqlx_postgres` | PostgreSQL repository implementations  | sqlx                  |
| `jwt`           | JWT token provider                     | jsonwebtoken          |
| `mocks`         | In-memory repositories for testing     | -                     |
| `tracing`       | Span instrumentation for all actions   | tracing               |
| `rate_limit`    | Rate limiting utilities                | futures               |

## Core Concepts

### Actions

Business logic is encapsulated in action structs. Each action accepts repository traits and executes a specific operation.

```rust
use enclave::actions::SignupAction;
use enclave::SecretString;

let signup = SignupAction::new(user_repo);
let password = SecretString::new("password123");
let user = signup.execute("user@example.com", &password).await?;
```

Available actions:

| Action                   | Purpose                         |
| ------------------------ | ------------------------------- |
| `SignupAction`           | Register new user               |
| `LoginAction`            | Authenticate user, return token |
| `LogoutAction`           | Revoke token (stateful only)    |
| `ForgotPasswordAction`   | Create password reset token     |
| `ResetPasswordAction`    | Reset password with token       |
| `RefreshTokenAction`     | Issue new token (stateful only) |
| `SendVerificationAction` | Create email verification token |
| `VerifyEmailAction`      | Mark email as verified          |
| `ChangePasswordAction`   | Change password (authenticated) |
| `UpdateUserAction`       | Update user profile             |
| `DeleteUserAction`       | Delete user account             |
| `GetUserAction`          | Retrieve user by ID             |

### Repository Traits

Storage is abstracted through traits. Implement these for custom backends.

| Trait                         | Purpose                                      |
| ----------------------------- | -------------------------------------------- |
| `UserRepository`              | User CRUD                                    |
| `TokenRepository`             | Token creation, lookup                       |
| `StatefulTokenRepository`     | Token revocation (extends `TokenRepository`) |
| `PasswordResetRepository`     | Password reset tokens                        |
| `EmailVerificationRepository` | Email verification tokens                    |
| `RateLimiterRepository`       | Login attempt tracking                       |
| `PasswordHasher`              | Password hashing and verification            |

## Custom Implementations

All storage and crypto operations are trait-based. Implement these traits to use your own database, cache, or hashing algorithm.

### UserRepository

```rust
use enclave::{UserRepository, User, AuthError};
use async_trait::async_trait;

#[async_trait]
impl UserRepository for MyUserStore {
    async fn find_user_by_id(&self, id: i32) -> Result<Option<User>, AuthError>;
    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, AuthError>;
    async fn create_user(&self, email: &str, hashed_password: &str) -> Result<User, AuthError>;
    async fn update_password(&self, user_id: i32, hashed_password: &str) -> Result<(), AuthError>;
    async fn verify_email(&self, user_id: i32) -> Result<(), AuthError>;
    async fn update_user(&self, user_id: i32, name: &str, email: &str) -> Result<User, AuthError>;
    async fn delete_user(&self, user_id: i32) -> Result<(), AuthError>;
}
```

The `User` struct:

```rust
pub struct User {
    pub id: i32,
    pub email: String,
    pub name: String,
    pub hashed_password: String,  // Never serialized
    pub email_verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
```

### TokenRepository

Base trait for token operations. Works for both stateless (JWT) and stateful tokens.

```rust
use enclave::{TokenRepository, AccessToken, AuthError};
use enclave::repository::CreateTokenOptions;
use chrono::{DateTime, Utc};
use async_trait::async_trait;

#[async_trait]
impl TokenRepository for MyTokenStore {
    async fn create_token(
        &self,
        user_id: i32,
        expires_at: DateTime<Utc>,
    ) -> Result<AccessToken, AuthError>;

    async fn create_token_with_options(
        &self,
        user_id: i32,
        expires_at: DateTime<Utc>,
        options: CreateTokenOptions,
    ) -> Result<AccessToken, AuthError>;

    async fn find_token(&self, token: &str) -> Result<Option<AccessToken>, AuthError>;
}
```

### StatefulTokenRepository

Extends `TokenRepository` with revocation. Required for logout and refresh-token endpoints.

```rust
use enclave::{StatefulTokenRepository, AuthError};
use async_trait::async_trait;

#[async_trait]
impl StatefulTokenRepository for MyTokenStore {
    async fn revoke_token(&self, token: &str) -> Result<(), AuthError>;
    async fn revoke_all_user_tokens(&self, user_id: i32) -> Result<(), AuthError>;
    async fn touch_token(&self, token: &str) -> Result<(), AuthError>;
    async fn prune_expired(&self) -> Result<u64, AuthError>;
}
```

### PasswordResetRepository

```rust
use enclave::{PasswordResetRepository, PasswordResetToken, AuthError};
use chrono::{DateTime, Utc};
use async_trait::async_trait;

#[async_trait]
impl PasswordResetRepository for MyResetStore {
    async fn create_reset_token(
        &self,
        user_id: i32,
        expires_at: DateTime<Utc>,
    ) -> Result<PasswordResetToken, AuthError>;

    async fn find_reset_token(&self, token: &str) -> Result<Option<PasswordResetToken>, AuthError>;
    async fn delete_reset_token(&self, token: &str) -> Result<(), AuthError>;
}
```

### EmailVerificationRepository

```rust
use enclave::{EmailVerificationRepository, EmailVerificationToken, AuthError};
use chrono::{DateTime, Utc};
use async_trait::async_trait;

#[async_trait]
impl EmailVerificationRepository for MyVerificationStore {
    async fn create_verification_token(
        &self,
        user_id: i32,
        expires_at: DateTime<Utc>,
    ) -> Result<EmailVerificationToken, AuthError>;

    async fn find_verification_token(
        &self,
        token: &str,
    ) -> Result<Option<EmailVerificationToken>, AuthError>;

    async fn delete_verification_token(&self, token: &str) -> Result<(), AuthError>;
}
```

### RateLimiterRepository

```rust
use enclave::{RateLimiterRepository, AuthError};
use chrono::{DateTime, Utc};
use async_trait::async_trait;

#[async_trait]
impl RateLimiterRepository for MyRateLimiter {
    async fn record_attempt(
        &self,
        email: &str,
        success: bool,
        ip_address: Option<&str>,
    ) -> Result<(), AuthError>;

    async fn get_recent_failed_attempts(
        &self,
        email: &str,
        since: DateTime<Utc>,
    ) -> Result<u32, AuthError>;

    async fn clear_attempts(&self, email: &str) -> Result<(), AuthError>;
}
```

### PasswordHasher

```rust
use enclave::crypto::PasswordHasher;
use enclave::AuthError;

impl PasswordHasher for MyHasher {
    fn hash(&self, password: &str) -> Result<String, AuthError>;
    fn verify(&self, password: &str, hash: &str) -> Result<bool, AuthError>;
}
```

### Token Hashing

Tokens must be hashed before storage. Use the provided `hash_token` function:

```rust
use enclave::crypto::hash_token;

let plain_token = "abc123...";
let hashed = hash_token(plain_token);  // SHA-256 hex string
// Store `hashed` in database, return `plain_token` to client
```

### Token Generation

```rust
use enclave::crypto::{generate_token, generate_token_default};

let token = generate_token(48);       // 48 alphanumeric characters
let token = generate_token_default(); // 32 characters (default)
```

### Stateful vs Stateless Tokens

**Stateful tokens** (database-backed) support revocation:

- Use `StatefulTokenRepository`
- `LogoutAction` and `RefreshTokenAction` available
- PostgreSQL implementation provided

**Stateless tokens** (JWT) cannot be revoked server-side:

- Use `TokenRepository` only
- No logout/refresh endpoints
- Use `stateless_auth_routes` with actix

## Configuration

### Password Policy

```rust
use enclave::PasswordPolicy;

// Default: 8-128 characters
let policy = PasswordPolicy::default();

// Strict: 12+ chars with requirements
let policy = PasswordPolicy::strict();

// Custom
let policy = PasswordPolicy::new()
    .min(10)
    .max(64)
    .require_uppercase()
    .require_lowercase()
    .require_digit()
    .require_special()
    .disallowed_passwords(vec!["password".into(), "123456".into()]);

policy.validate("MyP@ssw0rd")?;
```

### Password Hasher

```rust
use enclave::{Argon2Hasher, PasswordHasher};

// Default parameters
let hasher = Argon2Hasher::default();

// OWASP recommended (64 MiB, 3 iterations, 4 threads)
let hasher = Argon2Hasher::production();

// Custom parameters (memory_cost, time_cost, parallelism)
let hasher = Argon2Hasher::new(65536, 3, 4);

let hash = hasher.hash("password")?;
let valid = hasher.verify("password", &hash)?;
```

### Token Expiry

```rust
use enclave::config::{AuthConfig, TokenConfig};
use chrono::Duration;

let config = AuthConfig {
    tokens: TokenConfig {
        access_token_expiry: Duration::hours(1),
        password_reset_expiry: Duration::minutes(30),
        email_verification_expiry: Duration::hours(24),
        ..Default::default()
    },
    ..Default::default()
};
```

### Rate Limiting

```rust
use enclave::config::RateLimitConfig;
use chrono::Duration;

let config = RateLimitConfig {
    max_failed_attempts: 5,
    lockout_duration: Duration::minutes(15),
};
```

## HTTP Layer (actix)

Requires `features = ["actix"]`.

### Routes

```rust
use actix_web::{App, web};
use enclave::api::actix::auth_routes;

App::new()
    .app_data(web::Data::new(user_repo))
    .app_data(web::Data::new(token_repo))
    .app_data(web::Data::new(rate_limiter))
    .app_data(web::Data::new(password_reset_repo))
    .app_data(web::Data::new(email_verification_repo))
    .configure(auth_routes::<
        UserRepo,
        TokenRepo,  // Must implement StatefulTokenRepository
        RateLimiterRepo,
        PasswordResetRepo,
        EmailVerificationRepo,
    >)
```

For JWT (stateless tokens), use `stateless_auth_routes`:

```rust
use enclave::api::actix::stateless_auth_routes;

// No logout or refresh-token endpoints
App::new()
    .configure(stateless_auth_routes::<...>)
```

### Endpoints

**Stateful routes** (`auth_routes`):

| Method | Path                  | Description      |
| ------ | --------------------- | ---------------- |
| POST   | /auth/register        | Create account   |
| POST   | /auth/login           | Login            |
| POST   | /auth/logout          | Revoke token     |
| GET    | /auth/me              | Get current user |
| PUT    | /auth/me              | Update profile   |
| POST   | /auth/change-password | Change password  |
| POST   | /auth/forgot-password | Request reset    |
| POST   | /auth/reset-password  | Reset with token |
| POST   | /auth/refresh-token   | Refresh token    |
| POST   | /auth/verify-email    | Verify email     |

**Stateless routes** (`stateless_auth_routes`):

Same as above, minus `/auth/logout` and `/auth/refresh-token`.

## PostgreSQL (sqlx_postgres)

Requires `features = ["sqlx_postgres"]`.

### Setup

1. Run migrations:

```bash
sqlx migrate run
```

2. Create repositories:

```rust
use enclave::postgres::{
    PostgresUserRepository,
    PostgresTokenRepository,
    PostgresRateLimiterRepository,
    PostgresPasswordResetRepository,
    PostgresEmailVerificationRepository,
};

let pool = PgPoolOptions::new()
    .connect("postgres://user:pass@localhost/db")
    .await?;

let user_repo = PostgresUserRepository::new(pool.clone());
let token_repo = PostgresTokenRepository::new(pool.clone());
// ...
```

### Tables

Migrations create:

- `users` - User accounts
- `access_tokens` - Session tokens (hashed)
- `password_reset_tokens` - Reset tokens (hashed)
- `email_verification_tokens` - Verification tokens (hashed)
- `login_attempts` - Rate limiting data

## JWT (jwt)

Requires `features = ["jwt"]`.

```rust
use enclave::jwt::{JwtConfig, JwtService, JwtTokenProvider};

let config = JwtConfig::new("secret-key-at-least-32-bytes-long")
    .with_access_expiry(chrono::Duration::minutes(15))
    .with_issuer("my-app");

let service = JwtService::new(config);
let provider = JwtTokenProvider::new(service);

// provider implements TokenRepository (not StatefulTokenRepository)
```

## Security Notes

**Password hashing**: Uses Argon2id. Tokens are hashed with SHA-256 before storage.

**User enumeration**: `ForgotPasswordAction` returns success regardless of whether the email exists.

**Token storage**: Plain tokens are never stored. Only hashed values are persisted.

**Rate limiting**: Tracks failed attempts per email. Configurable lockout threshold and duration.

## Examples

```bash
# PostgreSQL server
cargo run --example postgres_server --features "actix sqlx_postgres"

# JWT server (in-memory storage)
cargo run --example jwt_server --features "actix jwt mocks"
```

Test with curl:

```bash
# Register
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password123"}'

# Login
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password123"}'

# Protected endpoint
curl http://localhost:8080/auth/me \
  -H "Authorization: Bearer <token>"
```

## License

MIT
