# Enclave

Authentication library for Rust applications.

Enclave provides building blocks for user authentication: password hashing, token management, rate limiting, and optional HTTP/database integrations. Uses a trait-based architecture for custom storage backends.

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

| Feature         | Description                            |
| --------------- | -------------------------------------- |
| `actix`         | HTTP handlers for actix-web            |
| `axum_api`      | HTTP handlers for Axum                 |
| `sqlx_postgres` | PostgreSQL repository implementations  |
| `sqlx_sqlite`   | SQLite repository implementations      |
| `jwt`           | JWT token provider                     |
| `mocks`         | In-memory repositories for testing     |
| `tracing`       | Span instrumentation for all actions   |
| `rate_limit`    | Rate limiting utilities                |
| `magic_link`    | Passwordless magic link authentication |
| `sessions`      | Cookie-based session authentication    |
| `audit_log`     | Security event audit logging           |
| `teams`         | Multi-tenant team support              |

## Quick Start

```rust
use enclave::actions::SignupAction;
use enclave::{MockUserRepository, SecretString};

let user_repo = MockUserRepository::new();
let signup = SignupAction::new(user_repo);

let password = SecretString::new("secure_password123");
let user = signup.execute("user@example.com", &password).await?;
```

## Actions

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
| `RequestMagicLinkAction` | Create magic link token         |
| `VerifyMagicLinkAction`  | Login via magic link            |

## Repository Traits

| Trait                         | Purpose                                      |
| ----------------------------- | -------------------------------------------- |
| `UserRepository`              | User CRUD                                    |
| `TokenRepository`             | Token creation, lookup                       |
| `StatefulTokenRepository`     | Token revocation (extends `TokenRepository`) |
| `PasswordResetRepository`     | Password reset tokens                        |
| `EmailVerificationRepository` | Email verification tokens                    |
| `RateLimiterRepository`       | Login attempt tracking                       |
| `MagicLinkRepository`         | Magic link tokens                            |

## Examples

```bash
# Actix + PostgreSQL
cargo run --example postgres_server --features "actix sqlx_postgres"

# Actix + JWT
cargo run --example jwt_server --features "actix jwt mocks"

# Axum + PostgreSQL
cargo run --example axum_postgres_server --features "axum_api sqlx_postgres"

# Axum + JWT
cargo run --example axum_jwt_server --features "axum_api jwt mocks"
```

## Documentation

- [API Documentation](https://docs.rs/enclave)
- [Security Policy](./SECURITY.md)

## License

MIT
