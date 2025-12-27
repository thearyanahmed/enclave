/**
 * @typedef {{ type: 'Signup' }} AuditEventType_Signup
 */

/**
 * @typedef {{ type: 'LoginSuccess' }} AuditEventType_LoginSuccess
 */

/**
 * @typedef {{ type: 'LoginFailed' }} AuditEventType_LoginFailed
 */

/**
 * @typedef {{ type: 'Logout' }} AuditEventType_Logout
 */

/**
 * @typedef {{ type: 'PasswordChanged' }} AuditEventType_PasswordChanged
 */

/**
 * @typedef {{ type: 'PasswordResetRequested' }} AuditEventType_PasswordResetRequested
 */

/**
 * @typedef {{ type: 'PasswordReset' }} AuditEventType_PasswordReset
 */

/**
 * @typedef {{ type: 'EmailVerificationSent' }} AuditEventType_EmailVerificationSent
 */

/**
 * @typedef {{ type: 'EmailVerified' }} AuditEventType_EmailVerified
 */

/**
 * @typedef {{ type: 'TokenRefreshed' }} AuditEventType_TokenRefreshed
 */

/**
 * @typedef {{ type: 'AccountDeleted' }} AuditEventType_AccountDeleted
 */

/**
 * Types of authentication events that can be logged.
 *
 * @typedef {(AuditEventType_Signup | AuditEventType_LoginSuccess | AuditEventType_LoginFailed | AuditEventType_Logout | AuditEventType_PasswordChanged | AuditEventType_PasswordResetRequested | AuditEventType_PasswordReset | AuditEventType_EmailVerificationSent | AuditEventType_EmailVerified | AuditEventType_TokenRefreshed | AuditEventType_AccountDeleted)} AuditEventType
 */
