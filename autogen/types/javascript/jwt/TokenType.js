/**
 * Short-lived access token for API requests.
 *
 * @typedef {{ type: 'Access' }} TokenType_Access
 */

/**
 * Long-lived refresh token for obtaining new access tokens.
 *
 * @typedef {{ type: 'Refresh' }} TokenType_Refresh
 */

/**
 * Type of JWT token.
 *
 * @typedef {(TokenType_Access | TokenType_Refresh)} TokenType
 */
