#![allow(clippy::significant_drop_tightening)]

use std::collections::HashMap;
use std::sync::RwLock;
use std::sync::atomic::{AtomicI32, Ordering};

use async_trait::async_trait;
use chrono::Utc;

use super::PermissionSet;
use super::repository::{
    CreateInvitation, CreateMembership, CreateTeam, TeamInvitationRepository,
    TeamMemberPermissionRepository, TeamMembershipRepository, TeamRepository,
    UserTeamContextRepository,
};
use super::traits::{Action, Resource};
use super::types::{Team, TeamInvitation, TeamMembership, UserTeamContext};
use crate::AuthError;

pub struct MockTeamRepository {
    teams: RwLock<HashMap<i32, Team>>,
    next_id: AtomicI32,
}

impl MockTeamRepository {
    pub fn new() -> Self {
        Self {
            teams: RwLock::new(HashMap::new()),
            next_id: AtomicI32::new(1),
        }
    }
}

impl Default for MockTeamRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TeamRepository for MockTeamRepository {
    async fn create(&self, data: CreateTeam) -> Result<Team, AuthError> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let now = Utc::now();
        let team = Team {
            id,
            name: data.name,
            slug: data.slug,
            owner_id: data.owner_id,
            created_at: now,
            updated_at: now,
        };

        let mut teams = self
            .teams
            .write()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        teams.insert(id, team.clone());

        Ok(team)
    }

    async fn find_by_id(&self, id: i32) -> Result<Option<Team>, AuthError> {
        let teams = self
            .teams
            .read()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        Ok(teams.get(&id).cloned())
    }

    async fn find_by_slug(&self, slug: &str) -> Result<Option<Team>, AuthError> {
        let teams = self
            .teams
            .read()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        Ok(teams.values().find(|t| t.slug == slug).cloned())
    }

    async fn update(
        &self,
        id: i32,
        name: Option<&str>,
        slug: Option<&str>,
    ) -> Result<Team, AuthError> {
        let mut teams = self
            .teams
            .write()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;

        let team = teams.get_mut(&id).ok_or(AuthError::NotFound)?;

        if let Some(n) = name {
            n.clone_into(&mut team.name);
        }
        if let Some(s) = slug {
            s.clone_into(&mut team.slug);
        }
        team.updated_at = Utc::now();

        Ok(team.clone())
    }

    async fn delete(&self, id: i32) -> Result<(), AuthError> {
        let mut teams = self
            .teams
            .write()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        teams.remove(&id);
        Ok(())
    }

    async fn find_by_owner(&self, owner_id: i32) -> Result<Vec<Team>, AuthError> {
        let teams = self
            .teams
            .read()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        Ok(teams
            .values()
            .filter(|t| t.owner_id == owner_id)
            .cloned()
            .collect())
    }

    async fn transfer_ownership(&self, team_id: i32, new_owner_id: i32) -> Result<Team, AuthError> {
        let mut teams = self
            .teams
            .write()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;

        let team = teams.get_mut(&team_id).ok_or(AuthError::NotFound)?;
        team.owner_id = new_owner_id;
        team.updated_at = Utc::now();

        Ok(team.clone())
    }
}

pub struct MockTeamMembershipRepository {
    memberships: RwLock<HashMap<i32, TeamMembership>>,
    next_id: AtomicI32,
}

impl MockTeamMembershipRepository {
    pub fn new() -> Self {
        Self {
            memberships: RwLock::new(HashMap::new()),
            next_id: AtomicI32::new(1),
        }
    }
}

impl Default for MockTeamMembershipRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TeamMembershipRepository for MockTeamMembershipRepository {
    async fn create(&self, data: CreateMembership) -> Result<TeamMembership, AuthError> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let now = Utc::now();
        let membership = TeamMembership {
            id,
            team_id: data.team_id,
            user_id: data.user_id,
            role: data.role,
            created_at: now,
            updated_at: now,
        };

        let mut memberships = self
            .memberships
            .write()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        memberships.insert(id, membership.clone());

        Ok(membership)
    }

    async fn find_by_id(&self, id: i32) -> Result<Option<TeamMembership>, AuthError> {
        let memberships = self
            .memberships
            .read()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        Ok(memberships.get(&id).cloned())
    }

    async fn find_by_team_and_user(
        &self,
        team_id: i32,
        user_id: i32,
    ) -> Result<Option<TeamMembership>, AuthError> {
        let memberships = self
            .memberships
            .read()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        Ok(memberships
            .values()
            .find(|m| m.team_id == team_id && m.user_id == user_id)
            .cloned())
    }

    async fn find_by_team(&self, team_id: i32) -> Result<Vec<TeamMembership>, AuthError> {
        let memberships = self
            .memberships
            .read()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        Ok(memberships
            .values()
            .filter(|m| m.team_id == team_id)
            .cloned()
            .collect())
    }

    async fn find_by_user(&self, user_id: i32) -> Result<Vec<TeamMembership>, AuthError> {
        let memberships = self
            .memberships
            .read()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        Ok(memberships
            .values()
            .filter(|m| m.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn update_role(&self, id: i32, role: &str) -> Result<TeamMembership, AuthError> {
        let mut memberships = self
            .memberships
            .write()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;

        let membership = memberships.get_mut(&id).ok_or(AuthError::NotFound)?;
        role.clone_into(&mut membership.role);
        membership.updated_at = Utc::now();

        Ok(membership.clone())
    }

    async fn delete(&self, id: i32) -> Result<(), AuthError> {
        let mut memberships = self
            .memberships
            .write()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        memberships.remove(&id);
        Ok(())
    }

    async fn delete_by_team_and_user(&self, team_id: i32, user_id: i32) -> Result<(), AuthError> {
        let mut memberships = self
            .memberships
            .write()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        memberships.retain(|_, m| !(m.team_id == team_id && m.user_id == user_id));
        Ok(())
    }
}

pub struct MockTeamInvitationRepository {
    invitations: RwLock<HashMap<i32, TeamInvitation>>,
    next_id: AtomicI32,
}

impl MockTeamInvitationRepository {
    pub fn new() -> Self {
        Self {
            invitations: RwLock::new(HashMap::new()),
            next_id: AtomicI32::new(1),
        }
    }
}

impl Default for MockTeamInvitationRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TeamInvitationRepository for MockTeamInvitationRepository {
    async fn create(&self, data: CreateInvitation) -> Result<TeamInvitation, AuthError> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let invitation = TeamInvitation {
            id,
            team_id: data.team_id,
            email: data.email,
            role: data.role,
            token_hash: data.token_hash,
            invited_by: data.invited_by,
            expires_at: data.expires_at,
            accepted_at: None,
            created_at: Utc::now(),
        };

        let mut invitations = self
            .invitations
            .write()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        invitations.insert(id, invitation.clone());

        Ok(invitation)
    }

    async fn find_by_id(&self, id: i32) -> Result<Option<TeamInvitation>, AuthError> {
        let invitations = self
            .invitations
            .read()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        Ok(invitations.get(&id).cloned())
    }

    async fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<TeamInvitation>, AuthError> {
        let invitations = self
            .invitations
            .read()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        Ok(invitations
            .values()
            .find(|i| i.token_hash == token_hash)
            .cloned())
    }

    async fn find_pending_by_team(&self, team_id: i32) -> Result<Vec<TeamInvitation>, AuthError> {
        let invitations = self
            .invitations
            .read()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        let now = Utc::now();
        Ok(invitations
            .values()
            .filter(|i| i.team_id == team_id && i.accepted_at.is_none() && i.expires_at > now)
            .cloned()
            .collect())
    }

    async fn find_pending_by_email(&self, email: &str) -> Result<Vec<TeamInvitation>, AuthError> {
        let invitations = self
            .invitations
            .read()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        let now = Utc::now();
        Ok(invitations
            .values()
            .filter(|i| i.email == email && i.accepted_at.is_none() && i.expires_at > now)
            .cloned()
            .collect())
    }

    async fn mark_accepted(&self, id: i32) -> Result<TeamInvitation, AuthError> {
        let mut invitations = self
            .invitations
            .write()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;

        let invitation = invitations.get_mut(&id).ok_or(AuthError::NotFound)?;
        invitation.accepted_at = Some(Utc::now());

        Ok(invitation.clone())
    }

    async fn delete(&self, id: i32) -> Result<(), AuthError> {
        let mut invitations = self
            .invitations
            .write()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        invitations.remove(&id);
        Ok(())
    }

    async fn delete_expired(&self) -> Result<u64, AuthError> {
        let mut invitations = self
            .invitations
            .write()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        let now = Utc::now();
        let before = invitations.len();
        invitations.retain(|_, i| i.expires_at > now);
        let after = invitations.len();
        #[allow(clippy::as_conversions)]
        Ok((before - after) as u64)
    }
}

pub struct MockTeamMemberPermissionRepository<R, A>
where
    R: Resource,
    A: Action,
{
    /// (`team_id`, `user_id`) -> permissions
    permissions: RwLock<HashMap<(i32, i32), PermissionSet<R, A>>>,
}

impl<R, A> MockTeamMemberPermissionRepository<R, A>
where
    R: Resource,
    A: Action,
{
    pub fn new() -> Self {
        Self {
            permissions: RwLock::new(HashMap::new()),
        }
    }
}

impl<R, A> Default for MockTeamMemberPermissionRepository<R, A>
where
    R: Resource,
    A: Action,
{
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl<R, A> TeamMemberPermissionRepository<R, A> for MockTeamMemberPermissionRepository<R, A>
where
    R: Resource,
    A: Action,
{
    async fn get_permissions(
        &self,
        team_id: i32,
        user_id: i32,
    ) -> Result<PermissionSet<R, A>, AuthError> {
        let permissions = self
            .permissions
            .read()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        Ok(permissions
            .get(&(team_id, user_id))
            .cloned()
            .unwrap_or_default())
    }

    async fn set_permissions(
        &self,
        team_id: i32,
        user_id: i32,
        perm_set: &PermissionSet<R, A>,
    ) -> Result<(), AuthError> {
        let mut permissions = self
            .permissions
            .write()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        permissions.insert((team_id, user_id), perm_set.clone());
        Ok(())
    }

    async fn grant_permission(
        &self,
        team_id: i32,
        user_id: i32,
        resource: R,
        action: A,
    ) -> Result<(), AuthError> {
        let mut permissions = self
            .permissions
            .write()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        let perm_set = permissions.entry((team_id, user_id)).or_default();
        perm_set.grant(resource, action);
        Ok(())
    }

    async fn revoke_permission(
        &self,
        team_id: i32,
        user_id: i32,
        resource: &R,
        action: &A,
    ) -> Result<(), AuthError> {
        let mut permissions = self
            .permissions
            .write()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        if let Some(perm_set) = permissions.get_mut(&(team_id, user_id)) {
            perm_set.revoke(resource, action);
        }
        Ok(())
    }

    async fn has_permission(
        &self,
        team_id: i32,
        user_id: i32,
        resource: &R,
        action: &A,
    ) -> Result<bool, AuthError> {
        let permissions = self
            .permissions
            .read()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        Ok(permissions
            .get(&(team_id, user_id))
            .is_some_and(|p| p.can(resource, action)))
    }
}

pub struct MockUserTeamContextRepository {
    contexts: RwLock<HashMap<i32, UserTeamContext>>,
}

impl MockUserTeamContextRepository {
    pub fn new() -> Self {
        Self {
            contexts: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for MockUserTeamContextRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl UserTeamContextRepository for MockUserTeamContextRepository {
    async fn get_context(&self, user_id: i32) -> Result<Option<UserTeamContext>, AuthError> {
        let contexts = self
            .contexts
            .read()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        Ok(contexts.get(&user_id).cloned())
    }

    async fn set_current_team(
        &self,
        user_id: i32,
        team_id: i32,
    ) -> Result<UserTeamContext, AuthError> {
        let mut contexts = self
            .contexts
            .write()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        let context = UserTeamContext {
            user_id,
            current_team_id: team_id,
            updated_at: Utc::now(),
        };
        contexts.insert(user_id, context.clone());
        Ok(context)
    }

    async fn clear_context(&self, user_id: i32) -> Result<(), AuthError> {
        let mut contexts = self
            .contexts
            .write()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        contexts.remove(&user_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, PartialEq, Eq, Hash, Debug)]
    enum TestResource {
        Project,
    }

    impl Resource for TestResource {
        fn as_str(&self) -> &'static str {
            "project"
        }

        fn from_str(s: &str) -> Option<Self> {
            (s == "project").then_some(Self::Project)
        }
    }

    #[derive(Clone, PartialEq, Debug)]
    enum TestAction {
        Create,
        All,
    }

    impl Action for TestAction {
        fn as_str(&self) -> &'static str {
            match self {
                Self::Create => "create",
                Self::All => "all",
            }
        }

        fn from_str(s: &str) -> Option<Self> {
            match s {
                "create" => Some(Self::Create),
                "all" => Some(Self::All),
                _ => None,
            }
        }

        fn is_all(&self) -> bool {
            matches!(self, Self::All)
        }
    }

    #[tokio::test]
    async fn test_team_repository() {
        let repo = MockTeamRepository::new();

        let team = repo
            .create(CreateTeam {
                name: "Test Team".into(),
                slug: "test-team".into(),
                owner_id: 1,
            })
            .await
            .unwrap();

        assert_eq!(team.name, "Test Team");
        assert_eq!(team.slug, "test-team");
        assert_eq!(team.owner_id, 1);

        let found = repo.find_by_id(team.id).await.unwrap();
        assert!(found.is_some());

        let by_slug = repo.find_by_slug("test-team").await.unwrap();
        assert!(by_slug.is_some());

        let updated = repo.update(team.id, Some("New Name"), None).await.unwrap();
        assert_eq!(updated.name, "New Name");

        repo.delete(team.id).await.unwrap();
        assert!(repo.find_by_id(team.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_membership_repository() {
        let repo = MockTeamMembershipRepository::new();

        let membership = repo
            .create(CreateMembership {
                team_id: 1,
                user_id: 2,
                role: "member".into(),
            })
            .await
            .unwrap();

        assert_eq!(membership.team_id, 1);
        assert_eq!(membership.user_id, 2);
        assert_eq!(membership.role, "member");

        let found = repo.find_by_team_and_user(1, 2).await.unwrap();
        assert!(found.is_some());

        let team_members = repo.find_by_team(1).await.unwrap();
        assert_eq!(team_members.len(), 1);

        let user_teams = repo.find_by_user(2).await.unwrap();
        assert_eq!(user_teams.len(), 1);

        let updated = repo.update_role(membership.id, "admin").await.unwrap();
        assert_eq!(updated.role, "admin");
    }

    #[tokio::test]
    async fn test_permission_repository() {
        let repo: MockTeamMemberPermissionRepository<TestResource, TestAction> =
            MockTeamMemberPermissionRepository::new();

        repo.grant_permission(1, 2, TestResource::Project, TestAction::Create)
            .await
            .unwrap();

        assert!(
            repo.has_permission(1, 2, &TestResource::Project, &TestAction::Create)
                .await
                .unwrap()
        );

        repo.revoke_permission(1, 2, &TestResource::Project, &TestAction::Create)
            .await
            .unwrap();

        assert!(
            !repo
                .has_permission(1, 2, &TestResource::Project, &TestAction::Create)
                .await
                .unwrap()
        );
    }
}
