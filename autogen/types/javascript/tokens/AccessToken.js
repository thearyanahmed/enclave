/**
 * An access token for API authentication.
 * 
 * The `token` field uses `SecretString` to prevent accidental logging.
 *
 * @typedef {AccessToken} AccessToken
 * @property {SecretString} token - The token string (plain-text on creation, hashed in storage).
 * @property {number} user_id - The user who owns this token.
 * @property {(string | null)} [name] - Optional name for the token (e.g., "mobile-app", "cli").
 * @property {string} expires_at - When the token expires.
 * @property {string} created_at - When the token was created.
 */
