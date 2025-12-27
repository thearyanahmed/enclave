/**
 * A user account in the authentication system.
 * 
 * This struct contains the core fields required for authentication. The
 * `hashed_password` field contains an Argon2 hash and is excluded from
 * serialization to prevent accidental exposure.
 * 
 * # Required Fields
 * 
 * When implementing [`UserRepository`], your database schema must include:
 * 
 * | Field | Type | Description |
 * |-------|------|-------------|
 * | `id` | `i32` | Unique identifier |
 * | `email` | `String` | User's email (used for login) |
 * | `name` | `String` | Display name |
 * | `hashed_password` | `String` | Argon2 password hash |
 * | `email_verified_at` | `Option<DateTime<Utc>>` | When email was verified |
 * | `created_at` | `DateTime<Utc>` | Creation timestamp |
 * | `updated_at` | `DateTime<Utc>` | Last update timestamp |
 * 
 * # Extending with Custom Fields
 * 
 * If you need additional fields (avatar, phone, etc.), use composition:
 * 
 * ```rust,ignore
 * struct AppUser {
 * auth: enclave::AuthUser,
 * avatar_url: Option<String>,
 * stripe_id: Option<String>,
 * }
 * ```
 *
 * @typedef {AuthUser} AuthUser
 * @property {number} id
 * @property {string} email
 * @property {string} name
 * @property {string} hashed_password
 * @property {(string | null)} [email_verified_at]
 * @property {string} created_at
 * @property {string} updated_at
 */
