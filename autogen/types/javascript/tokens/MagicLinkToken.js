/**
 * A one-time token for magic link login.
 * 
 * Tokens are hashed before storage and single-use (deleted after successful login).
 * The `token` field uses `SecretString` to prevent accidental logging.
 *
 * @typedef {MagicLinkToken} MagicLinkToken
 * @property {SecretString} token
 * @property {number} user_id
 * @property {string} expires_at
 * @property {string} created_at
 */
