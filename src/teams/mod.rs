mod actions;
mod permission_set;
mod repository;
mod traits;
mod types;

pub use actions::{
    AcceptInvitationAction, InvitationConfig, InviteToTeamAction, InviteToTeamInput,
    InviteToTeamOutput,
};
pub use permission_set::{PermissionSet, PermissionSetBuilder};
pub use repository::{
    CreateInvitation, CreateMembership, CreateTeam, TeamInvitationRepository,
    TeamMemberPermissionRepository, TeamMembershipRepository, TeamRepository,
    UserTeamContextRepository,
};
pub use traits::{Action, Permission, Resource, Role};
pub use types::{Team, TeamInvitation, TeamMembership, UserTeamContext};

#[cfg(feature = "mocks")]
mod mocks;

#[cfg(feature = "mocks")]
pub use mocks::{
    MockTeamInvitationRepository, MockTeamMemberPermissionRepository, MockTeamMembershipRepository,
    MockTeamRepository, MockUserTeamContextRepository,
};
