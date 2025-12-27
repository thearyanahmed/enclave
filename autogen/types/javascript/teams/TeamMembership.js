/**
 * Links a user to a team with a role.
 * 
 * The role is stored as a string in the database and parsed
 * using the user-defined `Role` trait implementation.
 *
 * @typedef {TeamMembership} TeamMembership
 * @property {number} id - Unique identifier.
 * @property {number} team_id - The team this membership belongs to.
 * @property {number} user_id - The user who is a member.
 * @property {string} role - The role as a string (parsed via `Role::from_str`).
 * @property {string} created_at - When the user joined the team.
 * @property {string} updated_at - When the membership was last updated.
 */
