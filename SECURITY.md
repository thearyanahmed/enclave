# Security Policy

> **WORK IN PROGRESS**: This security policy is under active development. Some sections may be incomplete or subject to change.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public GitHub issue
2. Email security concerns to the maintainers (see repository contacts)
3. Include a detailed description and steps to reproduce
4. Allow up to 48 hours for an initial response

We appreciate responsible disclosure and will credit researchers who report valid issues.

---

## Threat Model

### In Scope

Enclave protects against:

- **Credential stuffing**: Rate limiting on login (configurable attempts + lockout)
- **Password brute force**: Argon2id hashing with memory-hard parameters
- **Token theft via logs**: `SecretString` redacts tokens in Debug/Display
- **User enumeration on login**: Generic `InvalidCredentials` error for all failures
- **Token replay (JWT)**: Unique `jti` claim per token
- **Weak JWT secrets**: Minimum 32-byte secret requirement
- **Abuse of reset/verification flows**: Rate limiting on password reset and email verification

### Out of Scope

Enclave does **not** protect against:

- **Transport security**: You must use HTTPS. Tokens sent over HTTP can be intercepted.
- **CSRF attacks**: Implement CSRF protection in your application layer.
- **XSS attacks**: Sanitize user input; don't store tokens in localStorage if XSS is a risk.
- **Session fixation**: Use `rotate_tokens()` after privilege escalation.
- **Timing attacks on user enumeration**: Login timing may vary slightly.
- **Denial of service**: Use infrastructure-level rate limiting (nginx, cloudflare).
- **Insider threats**: Database access grants full control.

---

## Security Features

### Password Hashing

- **Algorithm**: Argon2id (OWASP 2024 recommended)
- **Default parameters**: 19 MiB memory, 2 iterations, 1 parallelism
- **Production preset**: `Argon2Hasher::production()` - 64 MiB, 3 iterations, 4 parallelism

### Token Security

- **Generation**: Cryptographically secure random bytes (`OsRng`)
- **Storage**: SHA-256 hashed before database storage
- **Format**: High-entropy alphanumeric strings (44+ characters)

### JWT Security

- **Algorithm**: HS256 (HMAC-SHA256)
- **Secret validation**: Minimum 32 bytes required
- **Claims**: `sub`, `exp`, `iat`, `jti` (unique ID), `typ` (access/refresh)
- **Token pair**: Short-lived access (15 min default) + long-lived refresh (7 days default)

### Rate Limiting

| Endpoint           | Default Limit     | Lockout    |
| ------------------ | ----------------- | ---------- |
| Login              | 5 failed attempts | 15 minutes |
| Password reset     | 5 requests        | 1 hour     |
| Email verification | 5 requests        | 1 hour     |

### Audit Logging

Enable `audit_log` feature for security event tracking:

- `Signup`, `LoginSuccess`, `LoginFailed`, `Logout`
- `PasswordChanged`, `PasswordResetRequested`, `PasswordReset`
- `EmailVerificationSent`, `EmailVerified`
- `TokenRefreshed`, `AccountDeleted`

---

## Deployment Requirements

### Required

1. **Use HTTPS**: All token transmission must be over TLS 1.2+
2. **Secure database connection**: Use SSL/TLS for PostgreSQL connections
3. **Environment variables**: Never commit secrets to version control
4. **JWT secret**: Use a cryptographically random 32+ byte secret

### Recommended

1. **Run token cleanup**: Periodically prune expired tokens from the database
2. **Enable audit logging**: Monitor for suspicious patterns
3. **Set appropriate CORS**: Use `cors::default()` or custom configuration in production
4. **Monitor rate limit events**: Alert on high failure rates

### JWT Secret Generation

```bash
# Generate a secure 32-byte secret (base64 encoded = 44 characters)
openssl rand -base64 32
```

---

## Configuration Hardening

### Production Password Policy

```rust
use enclave::PasswordPolicy;

let policy = PasswordPolicy::builder()
    .min_length(12)
    .require_uppercase(true)
    .require_lowercase(true)
    .require_digit(true)
    .require_special(true)
    .build();
```

### Production Argon2 Settings

```rust
use enclave::Argon2Hasher;

let hasher = Argon2Hasher::production();
```

### Strict Auth Configuration

```rust
use enclave::AuthConfig;

let config = AuthConfig::strict(); // 3 attempts, 30 min lockout
```

---

## Known Limitations

1. **HS256 only**: JWT uses symmetric signing. Asymmetric (RS256) not yet supported.
2. **No MFA/2FA**: Multi-factor authentication planned for v0.5.
3. **No session management**: Token-based only; no server-side session store.
4. **No OAuth2/Social login**: Use dedicated OAuth2 libraries.
5. **Single token type per user**: No device-specific token tracking yet.

---

## Security Changelog

### v0.2.0

- Added JWT secret minimum length validation (32+ bytes)
- Added `jti` claim to prevent JWT replay
- Added rate limiting to password reset endpoint
- Added rate limiting to email verification endpoint
- Added session revocation on password change
- Stabilized audit log feature
- Added `SecretString` wrapper for token handling

### v0.1.0

- Initial release with Argon2id password hashing
- SHA-256 token hashing
- Login rate limiting
