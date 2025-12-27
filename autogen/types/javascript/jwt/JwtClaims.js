/**
 * Claims embedded in a JWT token.
 *
 * @typedef {JwtClaims} JwtClaims
 * @property {string} sub - Subject - the user ID.
 * @property {number} exp - Expiration time (Unix timestamp).
 * @property {number} iat - Issued at time (Unix timestamp).
 * @property {string} jti - JWT ID - unique identifier for this token.
 * @property {TokenType} token_type - Token type (access or refresh).
 * @property {(string | null)} [iss] - Issuer (optional).
 * @property {(string | null)} [aud] - Audience (optional).
 */
