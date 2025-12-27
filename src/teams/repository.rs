//! Repository traits for team management.
//!
//! These traits define the storage interface for teams, memberships,
//! invitations, and permissions. Implement them for your database backend.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::PermissionSet;
use super::traits::{Action, Resource};
use super::types::{Team, TeamInvitation, TeamMembership, UserTeamContext};
use crate::AuthError;

/// Data for creating a new team.
#[derive(Debug, Clone)]
pub struct CreateTeam {
    /// Team name.
    pub name: String,
    /// URL-friendly slug.
    pub slug: String,
    /// User ID of the owner.
    pub owner_id: i32,
}

/// Data for creating a team membership.
#[derive(Debug, Clone)]
pub struct CreateMembership {
    /// Team ID.
    pub team_id: i32,
    /// User ID.
    pub user_id: i32,
    /// Role as string.
    pub role: String,
}

/// Data for creating a team invitation.
#[derive(Debug, Clone)]
pub struct CreateInvitation {
    /// Team ID.
    pub team_id: i32,
    /// Invitee email.
    pub email: String,
    /// Role to assign on acceptance.
    pub role: String,
    /// SHA-256 hash of the invitation token.
    pub token_hash: String,
    /// User ID of who sent the invitation.
    pub invited_by: i32,
    /// When the invitation expires.
    pub expires_at: DateTime<Utc>,
}

/// Repository for team CRUD operations.
#[async_trait]
pub trait TeamRepository: Send + Sync {
    /// Create a new team.
    async fn create(&self, data: CreateTeam) -> Result<Team, AuthError>;

    /// Find a team by ID.
    async fn find_by_id(&self, id: i32) -> Result<Option<Team>, AuthError>;

    /// Find a team by slug.
    async fn find_by_slug(&self, slug: &str) -> Result<Option<Team>, AuthError>;

    /// Update a team's name and/or slug.
    async fn update(
        &self,
        id: i32,
        name: Option<&str>,
        slug: Option<&str>,
    ) -> Result<Team, AuthError>;

    /// Delete a team.
    async fn delete(&self, id: i32) -> Result<(), AuthError>;

    /// List all teams owned by a user.
    async fn find_by_owner(&self, owner_id: i32) -> Result<Vec<Team>, AuthError>;

    /// Transfer ownership to another user.
    async fn transfer_ownership(&self, team_id: i32, new_owner_id: i32) -> Result<Team, AuthError>;
}

/// Repository for team membership operations.
#[async_trait]
pub trait TeamMembershipRepository: Send + Sync {
    /// Add a user to a team.
    async fn create(&self, data: CreateMembership) -> Result<TeamMembership, AuthError>;

    /// Find a membership by ID.
    async fn find_by_id(&self, id: i32) -> Result<Option<TeamMembership>, AuthError>;

    /// Find a user's membership in a team.
    async fn find_by_team_and_user(
        &self,
        team_id: i32,
        user_id: i32,
    ) -> Result<Option<TeamMembership>, AuthError>;

    /// List all members of a team.
    async fn find_by_team(&self, team_id: i32) -> Result<Vec<TeamMembership>, AuthError>;

    /// List all teams a user belongs to.
    async fn find_by_user(&self, user_id: i32) -> Result<Vec<TeamMembership>, AuthError>;

    /// Update a member's role.
    async fn update_role(&self, id: i32, role: &str) -> Result<TeamMembership, AuthError>;

    /// Remove a member from a team.
    async fn delete(&self, id: i32) -> Result<(), AuthError>;

    /// Remove a user from a team by team and user IDs.
    async fn delete_by_team_and_user(&self, team_id: i32, user_id: i32) -> Result<(), AuthError>;
}

/// Repository for team invitation operations.
#[async_trait]
pub trait TeamInvitationRepository: Send + Sync {
    /// Create a new invitation.
    async fn create(&self, data: CreateInvitation) -> Result<TeamInvitation, AuthError>;

    /// Find an invitation by ID.
    async fn find_by_id(&self, id: i32) -> Result<Option<TeamInvitation>, AuthError>;

    /// Find an invitation by token hash.
    async fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<TeamInvitation>, AuthError>;

    /// Find pending invitations for a team.
    async fn find_pending_by_team(&self, team_id: i32) -> Result<Vec<TeamInvitation>, AuthError>;

    /// Find pending invitations for an email.
    async fn find_pending_by_email(&self, email: &str) -> Result<Vec<TeamInvitation>, AuthError>;

    /// Mark an invitation as accepted.
    async fn mark_accepted(&self, id: i32) -> Result<TeamInvitation, AuthError>;

    /// Delete an invitation.
    async fn delete(&self, id: i32) -> Result<(), AuthError>;

    /// Delete expired invitations.
    async fn delete_expired(&self) -> Result<u64, AuthError>;
}

/// Repository for team member permissions.
///
/// This is separate from membership because permissions may be stored
/// differently (e.g., in a JSON column or separate table).
#[async_trait]
pub trait TeamMemberPermissionRepository<R, A>: Send + Sync
where
    R: Resource,
    A: Action,
{
    /// Get permissions for a team member.
    async fn get_permissions(
        &self,
        team_id: i32,
        user_id: i32,
    ) -> Result<PermissionSet<R, A>, AuthError>;

    /// Set permissions for a team member (replaces existing).
    async fn set_permissions(
        &self,
        team_id: i32,
        user_id: i32,
        permissions: &PermissionSet<R, A>,
    ) -> Result<(), AuthError>;

    /// Grant a single permission.
    async fn grant_permission(
        &self,
        team_id: i32,
        user_id: i32,
        resource: R,
        action: A,
    ) -> Result<(), AuthError>;

    /// Revoke a single permission.
    async fn revoke_permission(
        &self,
        team_id: i32,
        user_id: i32,
        resource: &R,
        action: &A,
    ) -> Result<(), AuthError>;

    /// Check if a member has a specific permission.
    async fn has_permission(
        &self,
        team_id: i32,
        user_id: i32,
        resource: &R,
        action: &A,
    ) -> Result<bool, AuthError>;
}

/// Repository for tracking user's current team context.
#[async_trait]
pub trait UserTeamContextRepository: Send + Sync {
    /// Get the user's current team context.
    async fn get_context(&self, user_id: i32) -> Result<Option<UserTeamContext>, AuthError>;

    /// Set the user's current team.
    async fn set_current_team(
        &self,
        user_id: i32,
        team_id: i32,
    ) -> Result<UserTeamContext, AuthError>;

    /// Clear the user's current team context.
    async fn clear_context(&self, user_id: i32) -> Result<(), AuthError>;
}
