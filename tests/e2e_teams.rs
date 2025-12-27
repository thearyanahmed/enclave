//! End-to-end tests for teams module.
//!
//! These tests demonstrate team workflows using mock repositories.
//! Run with: `cargo test --features "teams mocks" --test e2e_teams`

#![cfg(all(feature = "teams", feature = "mocks"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chrono::{Duration, Utc};

use enclave::teams::{
    Action, CreateInvitation, CreateMembership, CreateTeam, MockTeamInvitationRepository,
    MockTeamMemberPermissionRepository, MockTeamMembershipRepository, MockTeamRepository,
    MockUserTeamContextRepository, Permission, PermissionSet, PermissionSetBuilder, Resource, Role,
    TeamInvitationRepository, TeamMemberPermissionRepository, TeamMembershipRepository,
    TeamRepository, UserTeamContextRepository,
};

// Test role enum
#[derive(Clone, PartialEq, Debug)]
enum AppRole {
    Owner,
    Admin,
    Member,
}

impl Role for AppRole {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "owner" => Some(Self::Owner),
            "admin" => Some(Self::Admin),
            "member" => Some(Self::Member),
            _ => None,
        }
    }
}

// Test resource enum
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
enum AppResource {
    Project,
    Member,
    Settings,
    Billing,
}

impl Resource for AppResource {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::Member => "member",
            Self::Settings => "settings",
            Self::Billing => "billing",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "project" => Some(Self::Project),
            "member" => Some(Self::Member),
            "settings" => Some(Self::Settings),
            "billing" => Some(Self::Billing),
            _ => None,
        }
    }
}

// Test action enum
#[derive(Clone, PartialEq, Debug)]
enum AppAction {
    Create,
    Read,
    Update,
    Delete,
    All,
}

impl Action for AppAction {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Read => "read",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::All => "all",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "create" => Some(Self::Create),
            "read" => Some(Self::Read),
            "update" => Some(Self::Update),
            "delete" => Some(Self::Delete),
            "all" => Some(Self::All),
            _ => None,
        }
    }

    fn is_all(&self) -> bool {
        matches!(self, Self::All)
    }
}

// Test permission struct (demonstrates Permission trait implementation)
#[derive(Clone, PartialEq, Debug)]
#[allow(dead_code)]
struct AppPermission {
    resource: AppResource,
    action: AppAction,
}

impl Permission for AppPermission {
    type Resource = AppResource;
    type Action = AppAction;

    fn resource(&self) -> &Self::Resource {
        &self.resource
    }

    fn action(&self) -> &Self::Action {
        &self.action
    }
}

// Helper functions for role-based permission tests
fn owner_permissions() -> PermissionSet<AppResource, AppAction> {
    PermissionSetBuilder::new()
        .grant(AppResource::Project, AppAction::All)
        .grant(AppResource::Member, AppAction::All)
        .grant(AppResource::Settings, AppAction::All)
        .grant(AppResource::Billing, AppAction::All)
        .build()
}

fn admin_permissions() -> PermissionSet<AppResource, AppAction> {
    PermissionSetBuilder::new()
        .grant(AppResource::Project, AppAction::All)
        .grant(AppResource::Member, AppAction::All)
        .grant(AppResource::Settings, AppAction::Read)
        .build()
}

fn member_permissions() -> PermissionSet<AppResource, AppAction> {
    PermissionSetBuilder::new()
        .grant(AppResource::Project, AppAction::Create)
        .grant(AppResource::Project, AppAction::Read)
        .grant(AppResource::Project, AppAction::Update)
        .build()
}

#[tokio::test]
async fn test_team_creation_workflow() {
    let team_repo = MockTeamRepository::new();
    let membership_repo = MockTeamMembershipRepository::new();

    // Create a team
    let team = team_repo
        .create(CreateTeam {
            name: "Acme Corp".into(),
            slug: "acme-corp".into(),
            owner_id: 1,
        })
        .await
        .unwrap();

    assert_eq!(team.name, "Acme Corp");
    assert_eq!(team.slug, "acme-corp");
    assert_eq!(team.owner_id, 1);

    // Add owner as a member with owner role
    let owner_membership = membership_repo
        .create(CreateMembership {
            team_id: team.id,
            user_id: 1,
            role: AppRole::Owner.as_str().into(),
        })
        .await
        .unwrap();

    let parsed_role: AppRole = owner_membership.parse_role().unwrap();
    assert_eq!(parsed_role, AppRole::Owner);

    // Add another member
    let member = membership_repo
        .create(CreateMembership {
            team_id: team.id,
            user_id: 2,
            role: AppRole::Member.as_str().into(),
        })
        .await
        .unwrap();

    assert_eq!(member.team_id, team.id);
    assert_eq!(member.user_id, 2);

    // List team members
    let members = membership_repo.find_by_team(team.id).await.unwrap();
    assert_eq!(members.len(), 2);

    // Find user's teams
    let user_teams = membership_repo.find_by_user(1).await.unwrap();
    assert_eq!(user_teams.len(), 1);
    assert_eq!(user_teams.first().map(|t| t.team_id), Some(team.id));
}

#[tokio::test]
async fn test_team_invitation_workflow() {
    let team_repo = MockTeamRepository::new();
    let invitation_repo = MockTeamInvitationRepository::new();
    let membership_repo = MockTeamMembershipRepository::new();

    // Create a team
    let team = team_repo
        .create(CreateTeam {
            name: "Startup Inc".into(),
            slug: "startup-inc".into(),
            owner_id: 1,
        })
        .await
        .unwrap();

    // Create an invitation
    let invitation = invitation_repo
        .create(CreateInvitation {
            team_id: team.id,
            email: "newuser@example.com".into(),
            role: AppRole::Member.as_str().into(),
            token_hash: "hashed_token_123".into(),
            invited_by: 1,
            expires_at: Utc::now() + Duration::days(7),
        })
        .await
        .unwrap();

    assert_eq!(invitation.email, "newuser@example.com");
    assert!(!invitation.is_expired());
    assert!(!invitation.is_accepted());

    // Find by token hash (simulating clicking invitation link)
    let found = invitation_repo
        .find_by_token_hash("hashed_token_123")
        .await
        .unwrap();
    assert!(found.is_some());
    let found = found.unwrap();
    assert_eq!(found.id, invitation.id);

    // Find pending invitations for team
    let pending = invitation_repo.find_pending_by_team(team.id).await.unwrap();
    assert_eq!(pending.len(), 1);

    // Accept invitation
    let accepted = invitation_repo.mark_accepted(invitation.id).await.unwrap();
    assert!(accepted.is_accepted());

    // Create membership after acceptance
    let new_member = membership_repo
        .create(CreateMembership {
            team_id: team.id,
            user_id: 3, // New user's ID
            role: invitation.role.clone(),
        })
        .await
        .unwrap();

    assert_eq!(new_member.role, AppRole::Member.as_str());

    // Pending invitations should now be empty (accepted ones filtered out)
    let pending = invitation_repo.find_pending_by_team(team.id).await.unwrap();
    assert_eq!(pending.len(), 0);
}

#[tokio::test]
async fn test_expired_invitation_handling() {
    let invitation_repo = MockTeamInvitationRepository::new();

    // Create an expired invitation
    let expired = invitation_repo
        .create(CreateInvitation {
            team_id: 1,
            email: "expired@example.com".into(),
            role: "member".into(),
            token_hash: "expired_hash".into(),
            invited_by: 1,
            expires_at: Utc::now() - Duration::hours(1), // Already expired
        })
        .await
        .unwrap();

    assert!(expired.is_expired());

    // Create a valid invitation
    invitation_repo
        .create(CreateInvitation {
            team_id: 1,
            email: "valid@example.com".into(),
            role: "member".into(),
            token_hash: "valid_hash".into(),
            invited_by: 1,
            expires_at: Utc::now() + Duration::days(7),
        })
        .await
        .unwrap();

    // Pending should only return non-expired
    let pending = invitation_repo.find_pending_by_team(1).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(
        pending.first().map(|p| p.email.as_str()),
        Some("valid@example.com")
    );

    // Delete expired
    let deleted_count = invitation_repo.delete_expired().await.unwrap();
    assert_eq!(deleted_count, 1);
}

#[tokio::test]
async fn test_permission_management() {
    let permission_repo: MockTeamMemberPermissionRepository<AppResource, AppAction> =
        MockTeamMemberPermissionRepository::new();

    let team_id = 1;
    let user_id = 2;

    // Grant individual permissions
    permission_repo
        .grant_permission(team_id, user_id, AppResource::Project, AppAction::Create)
        .await
        .unwrap();
    permission_repo
        .grant_permission(team_id, user_id, AppResource::Project, AppAction::Read)
        .await
        .unwrap();

    // Check permissions
    assert!(
        permission_repo
            .has_permission(team_id, user_id, &AppResource::Project, &AppAction::Create)
            .await
            .unwrap()
    );
    assert!(
        permission_repo
            .has_permission(team_id, user_id, &AppResource::Project, &AppAction::Read)
            .await
            .unwrap()
    );
    assert!(
        !permission_repo
            .has_permission(team_id, user_id, &AppResource::Project, &AppAction::Delete)
            .await
            .unwrap()
    );

    // Revoke a permission
    permission_repo
        .revoke_permission(team_id, user_id, &AppResource::Project, &AppAction::Create)
        .await
        .unwrap();

    assert!(
        !permission_repo
            .has_permission(team_id, user_id, &AppResource::Project, &AppAction::Create)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn test_permission_set_with_all_action() {
    let permission_repo: MockTeamMemberPermissionRepository<AppResource, AppAction> =
        MockTeamMemberPermissionRepository::new();

    let team_id = 1;
    let admin_id = 2;

    // Set permissions using PermissionSet with "all" action
    let admin_perms = PermissionSetBuilder::new()
        .grant(AppResource::Project, AppAction::All)
        .grant(AppResource::Member, AppAction::Read)
        .build();

    permission_repo
        .set_permissions(team_id, admin_id, &admin_perms)
        .await
        .unwrap();

    // "All" should grant any action on that resource
    assert!(
        permission_repo
            .has_permission(team_id, admin_id, &AppResource::Project, &AppAction::Create)
            .await
            .unwrap()
    );
    assert!(
        permission_repo
            .has_permission(team_id, admin_id, &AppResource::Project, &AppAction::Delete)
            .await
            .unwrap()
    );

    // But not on other resources
    assert!(
        !permission_repo
            .has_permission(team_id, admin_id, &AppResource::Member, &AppAction::Delete)
            .await
            .unwrap()
    );
    assert!(
        permission_repo
            .has_permission(team_id, admin_id, &AppResource::Member, &AppAction::Read)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn test_role_based_permission_assignment() {
    let permission_repo: MockTeamMemberPermissionRepository<AppResource, AppAction> =
        MockTeamMemberPermissionRepository::new();

    let team_id = 1;

    // Assign permissions based on roles
    let owner_id = 1;
    let admin_id = 2;
    let member_id = 3;

    permission_repo
        .set_permissions(team_id, owner_id, &owner_permissions())
        .await
        .unwrap();
    permission_repo
        .set_permissions(team_id, admin_id, &admin_permissions())
        .await
        .unwrap();
    permission_repo
        .set_permissions(team_id, member_id, &member_permissions())
        .await
        .unwrap();

    // Owner can do everything
    assert!(
        permission_repo
            .has_permission(team_id, owner_id, &AppResource::Billing, &AppAction::Update)
            .await
            .unwrap()
    );

    // Admin cannot access billing
    assert!(
        !permission_repo
            .has_permission(team_id, admin_id, &AppResource::Billing, &AppAction::Read)
            .await
            .unwrap()
    );

    // Member cannot delete projects
    assert!(
        !permission_repo
            .has_permission(
                team_id,
                member_id,
                &AppResource::Project,
                &AppAction::Delete
            )
            .await
            .unwrap()
    );
    // But can create them
    assert!(
        permission_repo
            .has_permission(
                team_id,
                member_id,
                &AppResource::Project,
                &AppAction::Create
            )
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn test_user_team_context_switching() {
    let team_repo = MockTeamRepository::new();
    let context_repo = MockUserTeamContextRepository::new();

    let user_id = 1;

    // Create two teams
    let team1 = team_repo
        .create(CreateTeam {
            name: "Team Alpha".into(),
            slug: "team-alpha".into(),
            owner_id: user_id,
        })
        .await
        .unwrap();

    let team2 = team_repo
        .create(CreateTeam {
            name: "Team Beta".into(),
            slug: "team-beta".into(),
            owner_id: user_id,
        })
        .await
        .unwrap();

    // Initially no context
    assert!(context_repo.get_context(user_id).await.unwrap().is_none());

    // Set current team to team1
    let ctx = context_repo
        .set_current_team(user_id, team1.id)
        .await
        .unwrap();
    assert_eq!(ctx.current_team_id, team1.id);

    // Switch to team2
    let ctx = context_repo
        .set_current_team(user_id, team2.id)
        .await
        .unwrap();
    assert_eq!(ctx.current_team_id, team2.id);

    // Verify context persists
    let ctx = context_repo.get_context(user_id).await.unwrap().unwrap();
    assert_eq!(ctx.current_team_id, team2.id);

    // Clear context
    context_repo.clear_context(user_id).await.unwrap();
    assert!(context_repo.get_context(user_id).await.unwrap().is_none());
}

#[tokio::test]
async fn test_team_ownership_transfer() {
    let team_repo = MockTeamRepository::new();
    let membership_repo = MockTeamMembershipRepository::new();

    let original_owner = 1;
    let new_owner = 2;

    // Create team
    let team = team_repo
        .create(CreateTeam {
            name: "Transfer Test".into(),
            slug: "transfer-test".into(),
            owner_id: original_owner,
        })
        .await
        .unwrap();

    // Add memberships
    membership_repo
        .create(CreateMembership {
            team_id: team.id,
            user_id: original_owner,
            role: AppRole::Owner.as_str().into(),
        })
        .await
        .unwrap();

    membership_repo
        .create(CreateMembership {
            team_id: team.id,
            user_id: new_owner,
            role: AppRole::Admin.as_str().into(),
        })
        .await
        .unwrap();

    // Transfer ownership
    let updated_team = team_repo
        .transfer_ownership(team.id, new_owner)
        .await
        .unwrap();
    assert_eq!(updated_team.owner_id, new_owner);

    // Update roles accordingly
    let old_owner_membership = membership_repo
        .find_by_team_and_user(team.id, original_owner)
        .await
        .unwrap()
        .unwrap();
    membership_repo
        .update_role(old_owner_membership.id, AppRole::Admin.as_str())
        .await
        .unwrap();

    let new_owner_membership = membership_repo
        .find_by_team_and_user(team.id, new_owner)
        .await
        .unwrap()
        .unwrap();
    membership_repo
        .update_role(new_owner_membership.id, AppRole::Owner.as_str())
        .await
        .unwrap();

    // Verify roles updated
    let old_owner_membership = membership_repo
        .find_by_team_and_user(team.id, original_owner)
        .await
        .unwrap()
        .unwrap();
    let new_owner_membership = membership_repo
        .find_by_team_and_user(team.id, new_owner)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(old_owner_membership.role, AppRole::Admin.as_str());
    assert_eq!(new_owner_membership.role, AppRole::Owner.as_str());
}

#[tokio::test]
async fn test_member_removal() {
    let membership_repo = MockTeamMembershipRepository::new();

    let team_id = 1;

    // Add members
    membership_repo
        .create(CreateMembership {
            team_id,
            user_id: 1,
            role: "owner".into(),
        })
        .await
        .unwrap();

    let member = membership_repo
        .create(CreateMembership {
            team_id,
            user_id: 2,
            role: "member".into(),
        })
        .await
        .unwrap();

    assert_eq!(
        membership_repo.find_by_team(team_id).await.unwrap().len(),
        2
    );

    // Remove by ID
    membership_repo.delete(member.id).await.unwrap();
    assert_eq!(
        membership_repo.find_by_team(team_id).await.unwrap().len(),
        1
    );

    // Add another and remove by team+user
    membership_repo
        .create(CreateMembership {
            team_id,
            user_id: 3,
            role: "member".into(),
        })
        .await
        .unwrap();

    membership_repo
        .delete_by_team_and_user(team_id, 3)
        .await
        .unwrap();
    assert_eq!(
        membership_repo.find_by_team(team_id).await.unwrap().len(),
        1
    );
}

#[tokio::test]
async fn test_permission_set_json_serialization() {
    let perms: PermissionSet<AppResource, AppAction> = PermissionSetBuilder::new()
        .grant(AppResource::Project, AppAction::Create)
        .grant(AppResource::Project, AppAction::Read)
        .grant(AppResource::Settings, AppAction::All)
        .build();

    // Serialize to JSON
    let json = perms.to_json();
    assert!(json.contains("project"));
    assert!(json.contains("settings"));

    // Deserialize back
    let parsed: PermissionSet<AppResource, AppAction> =
        PermissionSet::from_json(&json).expect("should parse");

    assert!(parsed.can(&AppResource::Project, &AppAction::Create));
    assert!(parsed.can(&AppResource::Project, &AppAction::Read));
    assert!(!parsed.can(&AppResource::Project, &AppAction::Delete));
    assert!(parsed.can(&AppResource::Settings, &AppAction::Update)); // "all" grants this
}
