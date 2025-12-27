/**
 * A one-time token for password reset requests.
 * 
 * Tokens are hashed before storage and single-use (deleted after password change).
 * The `token` field uses `SecretString` to prevent accidental logging.
 *
 * @typedef {PasswordResetToken} PasswordResetToken
 * @property {SecretString} token
 * @property {number} user_id
 * @property {string} expires_at
 * @property {string} created_at
 */
