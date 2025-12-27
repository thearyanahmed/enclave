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

| Feature         | Description                            | Dependencies            |
| --------------- | -------------------------------------- | ----------------------- |
| `actix`         | HTTP handlers and routes for actix-web | actix-web, actix-cors   |
| `axum_api`      | HTTP handlers and routes for Axum      | axum, tower, tower-http |
| `sqlx_postgres` | PostgreSQL repository implementations  | sqlx                    |
| `jwt`           | JWT token provider                     | jsonwebtoken            |
| `mocks`         | In-memory repositories for testing     | -                       |
| `tracing`       | Span instrumentation for all actions   | tracing                 |
| `rate_limit`    | Rate limiting utilities                | futures                 |
| `magic_link`    | Passwordless magic link authentication | -                       |
| `teams`         | Multi-tenant team support              | -                       |

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
| `RequestMagicLinkAction` | Create magic link token         |
| `VerifyMagicLinkAction`  | Login via magic link            |

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
| `MagicLinkRepository`         | Magic link tokens                            |
| `PasswordHasher`              | Password hashing and verification            |

## Custom Implementations

All storage and crypto operations are trait-based. Implement these traits to use your own database, cache, or hashing algorithm.

### UserRepository

```rust
use enclave::{UserRepository, AuthUser, AuthError};
use async_trait::async_trait;

#[async_trait]
impl UserRepository for MyUserStore {
    async fn find_user_by_id(&self, id: i32) -> Result<Option<AuthUser>, AuthError>;
    async fn find_user_by_email(&self, email: &str) -> Result<Option<AuthUser>, AuthError>;
    async fn create_user(&self, email: &str, hashed_password: &str) -> Result<AuthUser, AuthError>;
    async fn update_password(&self, user_id: i32, hashed_password: &str) -> Result<(), AuthError>;
    async fn verify_email(&self, user_id: i32) -> Result<(), AuthError>;
    async fn update_user(&self, user_id: i32, name: &str, email: &str) -> Result<AuthUser, AuthError>;
    async fn delete_user(&self, user_id: i32) -> Result<(), AuthError>;
}
```

The `AuthUser` struct:

```rust
pub struct AuthUser {
    pub id: i32,
    pub email: String,
    pub name: String,
    pub hashed_password: String,  // Never serialized
    pub email_verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
```

`AuthUser` contains the core authentication fields. To add custom fields (avatar, roles, etc.), use composition:

```rust
pub struct AppUser {
    pub auth: enclave::AuthUser,
    pub avatar_url: Option<String>,
    pub role: String,
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

### MagicLinkRepository

Requires `features = ["magic_link"]`.

```rust
use enclave::{MagicLinkRepository, MagicLinkToken, AuthError};
use chrono::{DateTime, Utc};
use async_trait::async_trait;

#[async_trait]
impl MagicLinkRepository for MyMagicLinkStore {
    async fn create_magic_link_token(
        &self,
        user_id: i32,
        expires_at: DateTime<Utc>,
    ) -> Result<MagicLinkToken, AuthError>;

    async fn find_magic_link_token(&self, token: &str) -> Result<Option<MagicLinkToken>, AuthError>;
    async fn delete_magic_link_token(&self, token: &str) -> Result<(), AuthError>;
    async fn prune_expired(&self) -> Result<u64, AuthError>;
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
- Use `stateless_auth_routes` (actix) or `stateless_auth_routes` (axum)

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

**Magic link routes** (`magic_link_routes`, requires `magic_link` feature):

| Method | Path                    | Description          |
| ------ | ----------------------- | -------------------- |
| POST   | /auth/magic-link        | Request magic link   |
| POST   | /auth/magic-link/verify | Login via magic link |

## HTTP Layer (Axum)

Requires `features = ["axum_api"]`.

### Routes

Axum uses an `AppState` struct to hold all repositories:

```rust
use axum::Router;
use enclave::api::axum::{auth_routes, AppState};

let state = AppState {
    user_repo,
    token_repo,      // Must implement StatefulTokenRepository
    rate_limiter,
    password_reset,
    email_verification,
};

let app = Router::new()
    .nest("/auth", auth_routes::<
        UserRepo,
        TokenRepo,
        RateLimiterRepo,
        PasswordResetRepo,
        EmailVerificationRepo,
    >())
    .with_state(state);
```

For JWT (stateless tokens), use `stateless_auth_routes`:

```rust
use enclave::api::axum::{stateless_auth_routes, AppState};

// No logout or refresh-token endpoints
let app = Router::new()
    .nest("/auth", stateless_auth_routes::<...>())
    .with_state(state);
```

### CORS

```rust
use enclave::api::axum::cors;

let app = Router::new()
    .nest("/auth", auth_routes::<...>())
    .layer(cors::permissive())  // Development
    // .layer(cors::default(&["https://example.com"]))  // Production
    .with_state(state);
```

### Endpoints

Same endpoints as actix (see above).

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
    // PostgresMagicLinkRepository,  // requires "magic_link" feature
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
- `magic_link_tokens` - Magic link tokens (hashed, requires `magic_link` feature)

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

### Actix

```bash
# PostgreSQL server
cargo run --example postgres_server --features "actix sqlx_postgres"

# JWT server (in-memory storage)
cargo run --example jwt_server --features "actix jwt mocks"
```

### Axum

```bash
# PostgreSQL server
cargo run --example axum_postgres_server --features "axum_api sqlx_postgres"

# JWT server (in-memory storage)
cargo run --example axum_jwt_server --features "axum_api jwt mocks"
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

## Teams (teams)

Requires `features = ["teams"]`.

Multi-tenant team support with roles, permissions, and invitations.

### Types

```rust
use enclave::teams::{Team, TeamMembership, TeamInvitation, UserTeamContext};

// Team - organizational unit with name, slug, owner
// TeamMembership - links users to teams with roles
// TeamInvitation - pending invitation with expiry
// UserTeamContext - tracks user's currently selected team
```

### Custom Roles and Permissions

Define your own roles, resources, and actions:

```rust
use enclave::teams::{Role, Resource, Action, PermissionSet, PermissionSetBuilder};

#[derive(Clone, PartialEq)]
enum AppRole { Owner, Admin, Member }

impl Role for AppRole {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
        }
    }
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "owner" => Some(Self::Owner),
            "admin" => Some(Self::Admin),
            "member" => Some(Self::Member),
            _ => None,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum AppResource { Project, Settings, Billing }

impl Resource for AppResource {
    fn as_str(&self) -> &'static str { /* ... */ }
    fn from_str(s: &str) -> Option<Self> { /* ... */ }
}

#[derive(Clone, PartialEq)]
enum AppAction { Create, Read, Update, Delete, All }

impl Action for AppAction {
    fn as_str(&self) -> &'static str { /* ... */ }
    fn from_str(s: &str) -> Option<Self> { /* ... */ }
    fn is_all(&self) -> bool { matches!(self, Self::All) }
}
```

### Permission Sets

```rust
// Build permission sets
let admin_perms = PermissionSetBuilder::<AppResource, AppAction>::new()
    .grant(AppResource::Project, AppAction::All)
    .grant(AppResource::Settings, AppAction::Read)
    .build();

// Check permissions
if admin_perms.can(&AppResource::Project, &AppAction::Create) {
    // User can create projects
}

// Serialize to JSON for storage
let json = admin_perms.to_json();
let restored = PermissionSet::from_json(&json).unwrap();
```

### Repository Traits

| Trait                            | Purpose                |
| -------------------------------- | ---------------------- |
| `TeamRepository`                 | Team CRUD, ownership   |
| `TeamMembershipRepository`       | Member management      |
| `TeamInvitationRepository`       | Invitation lifecycle   |
| `TeamMemberPermissionRepository` | Permission management  |
| `UserTeamContextRepository`      | Team context switching |

### PostgreSQL Support

With `features = ["teams", "sqlx_postgres"]`:

```rust
use enclave::postgres::{
    PostgresTeamRepository,
    PostgresTeamMembershipRepository,
    PostgresTeamInvitationRepository,
    PostgresTeamMemberPermissionRepository,
    PostgresUserTeamContextRepository,
};

let team_repo = PostgresTeamRepository::new(pool.clone());
let membership_repo = PostgresTeamMembershipRepository::new(pool.clone());
let permission_repo: PostgresTeamMemberPermissionRepository<AppResource, AppAction> =
    PostgresTeamMemberPermissionRepository::new(pool.clone());
```

### Mock Repositories

With `features = ["teams", "mocks"]`:

```rust
use enclave::teams::{
    MockTeamRepository,
    MockTeamMembershipRepository,
    MockTeamInvitationRepository,
    MockTeamMemberPermissionRepository,
    MockUserTeamContextRepository,
};
```

## License

MIT
