/**
 * An invitation for a user to join a team.
 *
 * @typedef {TeamInvitation} TeamInvitation
 * @property {number} id - Unique identifier.
 * @property {number} team_id - The team being invited to.
 * @property {string} email - Email of the invitee.
 * @property {string} role - Role to assign when accepted (as string).
 * @property {string} token_hash - SHA-256 hash of the invitation token.
 * @property {number} invited_by - User ID of who sent the invitation.
 * @property {string} expires_at - When the invitation expires.
 * @property {(string | null)} [accepted_at] - When the invitation was accepted (if accepted).
 * @property {string} created_at - When the invitation was created.
 */
