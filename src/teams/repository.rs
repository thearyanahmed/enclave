use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::PermissionSet;
use super::traits::{Action, Resource};
use super::types::{Team, TeamInvitation, TeamMembership, UserTeamContext};
use crate::AuthError;

#[derive(Debug, Clone)]
pub struct CreateTeam {
    pub name: String,
    pub slug: String,
    pub owner_id: u64,
}

#[derive(Debug, Clone)]
pub struct CreateMembership {
    pub team_id: u64,
    pub user_id: u64,
    pub role: String,
}

#[derive(Debug, Clone)]
pub struct CreateInvitation {
    pub team_id: u64,
    pub email: String,
    pub role: String,
    pub token_hash: String,
    pub invited_by: u64,
    pub expires_at: DateTime<Utc>,
}

#[async_trait]
pub trait TeamRepository: Send + Sync {
    async fn create(&self, data: CreateTeam) -> Result<Team, AuthError>;
    async fn find_by_id(&self, id: u64) -> Result<Option<Team>, AuthError>;
    async fn find_by_slug(&self, slug: &str) -> Result<Option<Team>, AuthError>;
    async fn update(
        &self,
        id: u64,
        name: Option<&str>,
        slug: Option<&str>,
    ) -> Result<Team, AuthError>;
    async fn delete(&self, id: u64) -> Result<(), AuthError>;
    async fn find_by_owner(&self, owner_id: u64) -> Result<Vec<Team>, AuthError>;
    async fn transfer_ownership(&self, team_id: u64, new_owner_id: u64) -> Result<Team, AuthError>;
}

#[async_trait]
pub trait TeamMembershipRepository: Send + Sync {
    async fn create(&self, data: CreateMembership) -> Result<TeamMembership, AuthError>;
    async fn find_by_id(&self, id: u64) -> Result<Option<TeamMembership>, AuthError>;
    async fn find_by_team_and_user(
        &self,
        team_id: u64,
        user_id: u64,
    ) -> Result<Option<TeamMembership>, AuthError>;
    async fn find_by_team(&self, team_id: u64) -> Result<Vec<TeamMembership>, AuthError>;
    async fn find_by_user(&self, user_id: u64) -> Result<Vec<TeamMembership>, AuthError>;
    async fn update_role(&self, id: u64, role: &str) -> Result<TeamMembership, AuthError>;
    async fn delete(&self, id: u64) -> Result<(), AuthError>;
    async fn delete_by_team_and_user(&self, team_id: u64, user_id: u64) -> Result<(), AuthError>;
}

#[async_trait]
pub trait TeamInvitationRepository: Send + Sync {
    async fn create(&self, data: CreateInvitation) -> Result<TeamInvitation, AuthError>;
    async fn find_by_id(&self, id: u64) -> Result<Option<TeamInvitation>, AuthError>;
    async fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<TeamInvitation>, AuthError>;
    async fn find_pending_by_team(&self, team_id: u64) -> Result<Vec<TeamInvitation>, AuthError>;
    async fn find_pending_by_email(&self, email: &str) -> Result<Vec<TeamInvitation>, AuthError>;
    async fn mark_accepted(&self, id: u64) -> Result<TeamInvitation, AuthError>;
    async fn delete(&self, id: u64) -> Result<(), AuthError>;
    async fn delete_expired(&self) -> Result<u64, AuthError>;
}

/// separate from membership - permissions may be stored in JSON or separate table
#[async_trait]
pub trait TeamMemberPermissionRepository<R, A>: Send + Sync
where
    R: Resource,
    A: Action,
{
    async fn get_permissions(
        &self,
        team_id: u64,
        user_id: u64,
    ) -> Result<PermissionSet<R, A>, AuthError>;

    async fn set_permissions(
        &self,
        team_id: u64,
        user_id: u64,
        permissions: &PermissionSet<R, A>,
    ) -> Result<(), AuthError>;

    async fn grant_permission(
        &self,
        team_id: u64,
        user_id: u64,
        resource: R,
        action: A,
    ) -> Result<(), AuthError>;

    async fn revoke_permission(
        &self,
        team_id: u64,
        user_id: u64,
        resource: &R,
        action: &A,
    ) -> Result<(), AuthError>;

    async fn has_permission(
        &self,
        team_id: u64,
        user_id: u64,
        resource: &R,
        action: &A,
    ) -> Result<bool, AuthError>;
}

#[async_trait]
pub trait UserTeamContextRepository: Send + Sync {
    async fn get_context(&self, user_id: u64) -> Result<Option<UserTeamContext>, AuthError>;
    async fn set_current_team(
        &self,
        user_id: u64,
        team_id: u64,
    ) -> Result<UserTeamContext, AuthError>;
    async fn clear_context(&self, user_id: u64) -> Result<(), AuthError>;
}
