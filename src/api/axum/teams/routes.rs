//! Route configuration for Axum teams endpoints.

use axum::Router;
use axum::routing::{delete, get, post, put};

use super::handlers;
use crate::teams::{
    TeamInvitationRepository, TeamMembershipRepository, TeamRepository, UserTeamContextRepository,
};
use crate::{TokenRepository, UserRepository};

/// Application state for teams routes.
///
/// This struct holds all the repositories needed by the teams handlers.
/// It also includes user and token repositories for authentication.
#[derive(Clone)]
pub struct TeamsState<U, T, TM, MM, IM, CM> {
    /// User repository for user lookups.
    pub user_repo: U,
    /// Token repository for authentication.
    pub token_repo: T,
    /// Team repository for team CRUD operations.
    pub team_repo: TM,
    /// Membership repository for team membership operations.
    pub membership_repo: MM,
    /// Invitation repository for team invitation operations.
    pub invitation_repo: IM,
    /// Context repository for user's current team context.
    pub context_repo: CM,
}

/// Creates all team routes.
///
/// All routes require authentication via bearer token.
///
/// # Routes
///
/// ## Team CRUD
/// - `POST /` - Create a new team
/// - `GET /` - List user's teams
/// - `GET /:id` - Get team details
/// - `PUT /:id` - Update team
/// - `DELETE /:id` - Delete team
/// - `POST /:id/transfer` - Transfer ownership
///
/// ## Members
/// - `GET /:id/members` - List team members
/// - `POST /:id/members` - Add a member
/// - `PUT /:id/members/:user_id` - Update member role
/// - `DELETE /:id/members/:user_id` - Remove member
///
/// ## Invitations
/// - `POST /:id/invitations` - Create invitation
/// - `GET /:id/invitations` - List pending invitations
/// - `DELETE /:id/invitations/:invitation_id` - Cancel invitation
///
/// ## Context (mounted separately under /me/team)
/// - `GET /` - Get current team context
/// - `PUT /` - Set current team
/// - `DELETE /` - Clear current team
pub fn teams_routes<U, T, TM, MM, IM, CM>() -> Router<TeamsState<U, T, TM, MM, IM, CM>>
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    TM: TeamRepository + Clone + Send + Sync + 'static,
    MM: TeamMembershipRepository + Clone + Send + Sync + 'static,
    IM: TeamInvitationRepository + Clone + Send + Sync + 'static,
    CM: UserTeamContextRepository + Clone + Send + Sync + 'static,
{
    Router::new()
        // Team CRUD
        .route("/", post(handlers::create_team::<U, T, TM, MM, IM, CM>))
        .route("/", get(handlers::list_user_teams::<U, T, TM, MM, IM, CM>))
        .route("/:id", get(handlers::get_team::<U, T, TM, MM, IM, CM>))
        .route("/:id", put(handlers::update_team::<U, T, TM, MM, IM, CM>))
        .route(
            "/:id",
            delete(handlers::delete_team::<U, T, TM, MM, IM, CM>),
        )
        .route(
            "/:id/transfer",
            post(handlers::transfer_ownership::<U, T, TM, MM, IM, CM>),
        )
        // Members
        .route(
            "/:id/members",
            get(handlers::list_members::<U, T, TM, MM, IM, CM>),
        )
        .route(
            "/:id/members",
            post(handlers::add_member::<U, T, TM, MM, IM, CM>),
        )
        .route(
            "/:id/members/:user_id",
            put(handlers::update_member_role::<U, T, TM, MM, IM, CM>),
        )
        .route(
            "/:id/members/:user_id",
            delete(handlers::remove_member::<U, T, TM, MM, IM, CM>),
        )
        // Invitations
        .route(
            "/:id/invitations",
            post(handlers::create_invitation::<U, T, TM, MM, IM, CM>),
        )
        .route(
            "/:id/invitations",
            get(handlers::list_invitations::<U, T, TM, MM, IM, CM>),
        )
        .route(
            "/:id/invitations/:invitation_id",
            delete(handlers::delete_invitation::<U, T, TM, MM, IM, CM>),
        )
}

/// Creates the invitation acceptance route.
///
/// This is separate because it's mounted at `/invitations/accept` rather than
/// under `/teams/:id`.
///
/// # Routes
/// - `POST /accept` - Accept an invitation by token
pub fn invitation_routes<U, T, TM, MM, IM, CM>() -> Router<TeamsState<U, T, TM, MM, IM, CM>>
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    TM: TeamRepository + Clone + Send + Sync + 'static,
    MM: TeamMembershipRepository + Clone + Send + Sync + 'static,
    IM: TeamInvitationRepository + Clone + Send + Sync + 'static,
    CM: UserTeamContextRepository + Clone + Send + Sync + 'static,
{
    Router::new().route(
        "/accept",
        post(handlers::accept_invitation::<U, T, TM, MM, IM, CM>),
    )
}

/// Creates the team context routes for the current user.
///
/// These are mounted under `/me/team`.
///
/// # Routes
/// - `GET /` - Get current team context
/// - `PUT /` - Set current team
/// - `DELETE /` - Clear current team
pub fn context_routes<U, T, TM, MM, IM, CM>() -> Router<TeamsState<U, T, TM, MM, IM, CM>>
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    TM: TeamRepository + Clone + Send + Sync + 'static,
    MM: TeamMembershipRepository + Clone + Send + Sync + 'static,
    IM: TeamInvitationRepository + Clone + Send + Sync + 'static,
    CM: UserTeamContextRepository + Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/", get(handlers::get_current_team::<U, T, TM, MM, IM, CM>))
        .route("/", put(handlers::set_current_team::<U, T, TM, MM, IM, CM>))
        .route(
            "/",
            delete(handlers::clear_current_team::<U, T, TM, MM, IM, CM>),
        )
}
