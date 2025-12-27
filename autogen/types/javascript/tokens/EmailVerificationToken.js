/**
 * A one-time token sent to users to verify their email address.
 * 
 * The `token` field uses `SecretString` to prevent accidental logging.
 *
 * @typedef {EmailVerificationToken} EmailVerificationToken
 * @property {SecretString} token
 * @property {number} user_id
 * @property {string} expires_at
 * @property {string} created_at
 */
