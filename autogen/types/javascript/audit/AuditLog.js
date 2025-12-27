/**
 * A recorded authentication event for security auditing.
 * 
 * The `user_id` is `None` for failed login attempts where the user doesn't exist.
 * Use `metadata` for additional context (e.g., reason for failure).
 *
 * @typedef {AuditLog} AuditLog
 * @property {number} id
 * @property {(number | null)} [user_id]
 * @property {AuditEventType} event_type
 * @property {(string | null)} [ip_address]
 * @property {(string | null)} [user_agent]
 * @property {(string | null)} [metadata]
 * @property {string} created_at
 */
