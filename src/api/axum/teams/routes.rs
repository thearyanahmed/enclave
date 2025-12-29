use axum::Router;
use axum::routing::{delete, get, post, put};

use super::handlers;
use crate::teams::{
    TeamInvitationRepository, TeamMembershipRepository, TeamRepository, UserTeamContextRepository,
};
use crate::{TokenRepository, UserRepository};

#[derive(Clone)]
pub struct TeamsState<U, T, TM, MM, IM, CM> {
    pub user_repo: U,
    pub token_repo: T,
    pub team_repo: TM,
    pub membership_repo: MM,
    pub invitation_repo: IM,
    pub context_repo: CM,
}

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

/// mounted at `/invitations/accept` rather than under `/teams/:id`
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

/// mounted under `/me/team`
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
