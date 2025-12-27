/**
 * @typedef {{ type: 'UserNotFound' }} AuthError_UserNotFound
 */

/**
 * @typedef {{ type: 'UserAlreadyExists' }} AuthError_UserAlreadyExists
 */

/**
 * @typedef {{ type: 'InvalidCredentials' }} AuthError_InvalidCredentials
 */

/**
 * @typedef {{ type: 'InvalidEmail' }} AuthError_InvalidEmail
 */

/**
 * @typedef {{ type: 'InvalidPassword' }} AuthError_InvalidPassword
 */

/**
 * @typedef {{ type: 'PasswordHashError' }} AuthError_PasswordHashError
 */

/**
 * @typedef {{ type: 'TokenExpired' }} AuthError_TokenExpired
 */

/**
 * @typedef {{ type: 'TokenInvalid' }} AuthError_TokenInvalid
 */

/**
 * @typedef {{ type: 'EmailAlreadyVerified' }} AuthError_EmailAlreadyVerified
 */

/**
 * @typedef {{ type: 'TooManyAttempts' }} AuthError_TooManyAttempts
 */

/**
 * @typedef {{ type: 'NotFound' }} AuthError_NotFound
 */

/**
 * @typedef {{ type: 'Validation', value: ValidationError }} AuthError_Validation
 */

/**
 * @typedef {{ type: 'ConfigurationError', value: string }} AuthError_ConfigurationError
 */

/**
 * @typedef {{ type: 'DatabaseError', value: string }} AuthError_DatabaseError
 */

/**
 * @typedef {{ type: 'Internal', value: string }} AuthError_Internal
 */

/**
 * @typedef {{ type: 'Other', value: string }} AuthError_Other
 */

/**
 * @typedef {(AuthError_UserNotFound | AuthError_UserAlreadyExists | AuthError_InvalidCredentials | AuthError_InvalidEmail | AuthError_InvalidPassword | AuthError_PasswordHashError | AuthError_TokenExpired | AuthError_TokenInvalid | AuthError_EmailAlreadyVerified | AuthError_TooManyAttempts | AuthError_NotFound | AuthError_Validation | AuthError_ConfigurationError | AuthError_DatabaseError | AuthError_Internal | AuthError_Other)} AuthError
 */
