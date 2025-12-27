//! Multi-tenant team support.
//!
//! This module provides team management functionality,
//! enabling users to create organizations, invite members, and manage permissions.
//!
//! # Design Philosophy
//!
//! - **Composition over inheritance** - Extend `AuthUser` with your own types
//! - **Type-safe permissions** - User-defined Role, Resource, Action enums
//! - **Flexible storage** - Trait-based repositories for any backend
//!
//! # Example
//!
//! ```rust,ignore
//! use enclave::AuthUser;
//! use enclave::teams::{Team, TeamMembership, Role};
//!
//! // Define your roles
//! #[derive(Clone, PartialEq)]
//! enum AppRole {
//!     Owner,
//!     Admin,
//!     Member,
//! }
//!
//! impl Role for AppRole {
//!     fn as_str(&self) -> &'static str {
//!         match self {
//!             Self::Owner => "owner",
//!             Self::Admin => "admin",
//!             Self::Member => "member",
//!         }
//!     }
//!
//!     fn from_str(s: &str) -> Option<Self> {
//!         match s {
//!             "owner" => Some(Self::Owner),
//!             "admin" => Some(Self::Admin),
//!             "member" => Some(Self::Member),
//!             _ => None,
//!         }
//!     }
//! }
//!
//! // Compose AuthUser with team context
//! struct AppUser {
//!     auth: AuthUser,
//!     current_team: Option<Team>,
//! }
//! ```

mod permission_set;
mod repository;
mod traits;
mod types;

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
    MockTeamInvitationRepository, MockTeamMemberPermissionRepository,
    MockTeamMembershipRepository, MockTeamRepository, MockUserTeamContextRepository,
};
