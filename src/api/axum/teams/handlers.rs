use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::{Duration, Utc};

use super::middleware::TeamsAuthenticatedUser;
use super::routes::TeamsState;
use crate::api::{
    AcceptInvitationRequest, AddMemberRequest, CreateTeamRequest, ErrorResponse,
    InviteMemberRequest, MessageResponse, SetCurrentTeamRequest, TeamInvitationResponse,
    TeamMembershipResponse, TeamResponse, TransferOwnershipRequest, UpdateMemberRoleRequest,
    UpdateTeamRequest, UserTeamContextResponse,
};
use crate::teams::{
    CreateInvitation, CreateMembership, CreateTeam, TeamInvitationRepository,
    TeamMembershipRepository, TeamRepository, UserTeamContextRepository,
};
use crate::{TokenRepository, UserRepository, crypto};

pub async fn create_team<U, T, TM, MM, IM, CM>(
    State(state): State<TeamsState<U, T, TM, MM, IM, CM>>,
    user: TeamsAuthenticatedUser<U, T>,
    Json(body): Json<CreateTeamRequest>,
) -> impl IntoResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    TM: TeamRepository + Clone + Send + Sync + 'static,
    MM: TeamMembershipRepository + Clone + Send + Sync + 'static,
    IM: Clone + Send + Sync + 'static,
    CM: Clone + Send + Sync + 'static,
{
    let data = CreateTeam {
        name: body.name,
        slug: body.slug,
        owner_id: user.user().id,
    };

    match state.team_repo.create(data).await {
        Ok(team) => {
            // Add owner as a member with "owner" role
            let membership_data = CreateMembership {
                team_id: team.id,
                user_id: user.user().id,
                role: "owner".to_owned(),
            };
            if let Err(e) = state.membership_repo.create(membership_data).await {
                log::error!(target: "enclave_auth", "msg=\"failed to create owner membership\", error=\"{e}\"");
            }
            (StatusCode::CREATED, Json(TeamResponse::from(team))).into_response()
        }
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            (StatusCode::BAD_REQUEST, Json(error_response)).into_response()
        }
    }
}

pub async fn list_user_teams<U, T, TM, MM, IM, CM>(
    State(state): State<TeamsState<U, T, TM, MM, IM, CM>>,
    user: TeamsAuthenticatedUser<U, T>,
) -> impl IntoResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    TM: TeamRepository + Clone + Send + Sync + 'static,
    MM: TeamMembershipRepository + Clone + Send + Sync + 'static,
    IM: Clone + Send + Sync + 'static,
    CM: Clone + Send + Sync + 'static,
{
    // Get all memberships for the user
    match state.membership_repo.find_by_user(user.user().id).await {
        Ok(memberships) => {
            let mut teams = Vec::with_capacity(memberships.len());
            for membership in memberships {
                if let Ok(Some(team)) = state.team_repo.find_by_id(membership.team_id).await {
                    teams.push(TeamResponse::from(team));
                }
            }
            Json(teams).into_response()
        }
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
        }
    }
}

pub async fn get_team<U, T, TM, MM, IM, CM>(
    State(state): State<TeamsState<U, T, TM, MM, IM, CM>>,
    user: TeamsAuthenticatedUser<U, T>,
    Path(team_id): Path<i32>,
) -> impl IntoResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    TM: TeamRepository + Clone + Send + Sync + 'static,
    MM: TeamMembershipRepository + Clone + Send + Sync + 'static,
    IM: Clone + Send + Sync + 'static,
    CM: Clone + Send + Sync + 'static,
{
    // Check if user is a member of the team
    match state
        .membership_repo
        .find_by_team_and_user(team_id, user.user().id)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "not a member of this team".to_owned(),
                }),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::from(err)),
            )
                .into_response();
        }
    }

    match state.team_repo.find_by_id(team_id).await {
        Ok(Some(team)) => Json(TeamResponse::from(team)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "team not found".to_owned(),
            }),
        )
            .into_response(),
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
        }
    }
}

pub async fn update_team<U, T, TM, MM, IM, CM>(
    State(state): State<TeamsState<U, T, TM, MM, IM, CM>>,
    user: TeamsAuthenticatedUser<U, T>,
    Path(team_id): Path<i32>,
    Json(body): Json<UpdateTeamRequest>,
) -> impl IntoResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    TM: TeamRepository + Clone + Send + Sync + 'static,
    MM: TeamMembershipRepository + Clone + Send + Sync + 'static,
    IM: Clone + Send + Sync + 'static,
    CM: Clone + Send + Sync + 'static,
{
    // Check if user is the owner
    match state.team_repo.find_by_id(team_id).await {
        Ok(Some(team)) => {
            if team.owner_id != user.user().id {
                return (
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "only the team owner can update the team".to_owned(),
                    }),
                )
                    .into_response();
            }
        }
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "team not found".to_owned(),
                }),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::from(err)),
            )
                .into_response();
        }
    }

    match state
        .team_repo
        .update(team_id, body.name.as_deref(), body.slug.as_deref())
        .await
    {
        Ok(team) => Json(TeamResponse::from(team)).into_response(),
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            (StatusCode::BAD_REQUEST, Json(error_response)).into_response()
        }
    }
}

pub async fn delete_team<U, T, TM, MM, IM, CM>(
    State(state): State<TeamsState<U, T, TM, MM, IM, CM>>,
    user: TeamsAuthenticatedUser<U, T>,
    Path(team_id): Path<i32>,
) -> impl IntoResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    TM: TeamRepository + Clone + Send + Sync + 'static,
    MM: TeamMembershipRepository + Clone + Send + Sync + 'static,
    IM: Clone + Send + Sync + 'static,
    CM: Clone + Send + Sync + 'static,
{
    // Check if user is the owner
    match state.team_repo.find_by_id(team_id).await {
        Ok(Some(team)) => {
            if team.owner_id != user.user().id {
                return (
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "only the team owner can delete the team".to_owned(),
                    }),
                )
                    .into_response();
            }
        }
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "team not found".to_owned(),
                }),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::from(err)),
            )
                .into_response();
        }
    }

    match state.team_repo.delete(team_id).await {
        Ok(()) => (
            StatusCode::OK,
            Json(MessageResponse {
                message: "team deleted successfully".to_owned(),
            }),
        )
            .into_response(),
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
        }
    }
}

pub async fn transfer_ownership<U, T, TM, MM, IM, CM>(
    State(state): State<TeamsState<U, T, TM, MM, IM, CM>>,
    user: TeamsAuthenticatedUser<U, T>,
    Path(team_id): Path<i32>,
    Json(body): Json<TransferOwnershipRequest>,
) -> impl IntoResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    TM: TeamRepository + Clone + Send + Sync + 'static,
    MM: TeamMembershipRepository + Clone + Send + Sync + 'static,
    IM: Clone + Send + Sync + 'static,
    CM: Clone + Send + Sync + 'static,
{
    // Check if user is the owner
    match state.team_repo.find_by_id(team_id).await {
        Ok(Some(team)) => {
            if team.owner_id != user.user().id {
                return (
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "only the team owner can transfer ownership".to_owned(),
                    }),
                )
                    .into_response();
            }
        }
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "team not found".to_owned(),
                }),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::from(err)),
            )
                .into_response();
        }
    }

    // Check if new owner is a member of the team
    match state
        .membership_repo
        .find_by_team_and_user(team_id, body.new_owner_id)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "new owner must be a member of the team".to_owned(),
                }),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::from(err)),
            )
                .into_response();
        }
    }

    match state
        .team_repo
        .transfer_ownership(team_id, body.new_owner_id)
        .await
    {
        Ok(team) => Json(TeamResponse::from(team)).into_response(),
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            (StatusCode::BAD_REQUEST, Json(error_response)).into_response()
        }
    }
}

pub async fn list_members<U, T, TM, MM, IM, CM>(
    State(state): State<TeamsState<U, T, TM, MM, IM, CM>>,
    user: TeamsAuthenticatedUser<U, T>,
    Path(team_id): Path<i32>,
) -> impl IntoResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    TM: TeamRepository + Clone + Send + Sync + 'static,
    MM: TeamMembershipRepository + Clone + Send + Sync + 'static,
    IM: Clone + Send + Sync + 'static,
    CM: Clone + Send + Sync + 'static,
{
    // Check if user is a member of the team
    match state
        .membership_repo
        .find_by_team_and_user(team_id, user.user().id)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "not a member of this team".to_owned(),
                }),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::from(err)),
            )
                .into_response();
        }
    }

    match state.membership_repo.find_by_team(team_id).await {
        Ok(members) => {
            let responses: Vec<_> = members
                .into_iter()
                .map(TeamMembershipResponse::from)
                .collect();
            Json(responses).into_response()
        }
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
        }
    }
}

pub async fn add_member<U, T, TM, MM, IM, CM>(
    State(state): State<TeamsState<U, T, TM, MM, IM, CM>>,
    user: TeamsAuthenticatedUser<U, T>,
    Path(team_id): Path<i32>,
    Json(body): Json<AddMemberRequest>,
) -> impl IntoResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    TM: TeamRepository + Clone + Send + Sync + 'static,
    MM: TeamMembershipRepository + Clone + Send + Sync + 'static,
    IM: Clone + Send + Sync + 'static,
    CM: Clone + Send + Sync + 'static,
{
    // Check if user is the owner
    match state.team_repo.find_by_id(team_id).await {
        Ok(Some(team)) => {
            if team.owner_id != user.user().id {
                return (
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "only the team owner can add members".to_owned(),
                    }),
                )
                    .into_response();
            }
        }
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "team not found".to_owned(),
                }),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::from(err)),
            )
                .into_response();
        }
    }

    // Check if user is already a member
    match state
        .membership_repo
        .find_by_team_and_user(team_id, body.user_id)
        .await
    {
        Ok(Some(_)) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "user is already a member of this team".to_owned(),
                }),
            )
                .into_response();
        }
        Ok(None) => {}
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::from(err)),
            )
                .into_response();
        }
    }

    let data = CreateMembership {
        team_id,
        user_id: body.user_id,
        role: body.role,
    };

    match state.membership_repo.create(data).await {
        Ok(membership) => (
            StatusCode::CREATED,
            Json(TeamMembershipResponse::from(membership)),
        )
            .into_response(),
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            (StatusCode::BAD_REQUEST, Json(error_response)).into_response()
        }
    }
}

pub async fn update_member_role<U, T, TM, MM, IM, CM>(
    State(state): State<TeamsState<U, T, TM, MM, IM, CM>>,
    user: TeamsAuthenticatedUser<U, T>,
    Path((team_id, target_user_id)): Path<(i32, i32)>,
    Json(body): Json<UpdateMemberRoleRequest>,
) -> impl IntoResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    TM: TeamRepository + Clone + Send + Sync + 'static,
    MM: TeamMembershipRepository + Clone + Send + Sync + 'static,
    IM: Clone + Send + Sync + 'static,
    CM: Clone + Send + Sync + 'static,
{
    // Check if user is the owner
    match state.team_repo.find_by_id(team_id).await {
        Ok(Some(team)) => {
            if team.owner_id != user.user().id {
                return (
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "only the team owner can update member roles".to_owned(),
                    }),
                )
                    .into_response();
            }
        }
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "team not found".to_owned(),
                }),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::from(err)),
            )
                .into_response();
        }
    }

    // Find the membership
    let membership = match state
        .membership_repo
        .find_by_team_and_user(team_id, target_user_id)
        .await
    {
        Ok(Some(m)) => m,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "member not found".to_owned(),
                }),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::from(err)),
            )
                .into_response();
        }
    };

    match state
        .membership_repo
        .update_role(membership.id, &body.role)
        .await
    {
        Ok(updated) => Json(TeamMembershipResponse::from(updated)).into_response(),
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            (StatusCode::BAD_REQUEST, Json(error_response)).into_response()
        }
    }
}

pub async fn remove_member<U, T, TM, MM, IM, CM>(
    State(state): State<TeamsState<U, T, TM, MM, IM, CM>>,
    user: TeamsAuthenticatedUser<U, T>,
    Path((team_id, target_user_id)): Path<(i32, i32)>,
) -> impl IntoResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    TM: TeamRepository + Clone + Send + Sync + 'static,
    MM: TeamMembershipRepository + Clone + Send + Sync + 'static,
    IM: Clone + Send + Sync + 'static,
    CM: Clone + Send + Sync + 'static,
{
    // Get team to check ownership
    let team = match state.team_repo.find_by_id(team_id).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "team not found".to_owned(),
                }),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::from(err)),
            )
                .into_response();
        }
    };

    // Only owner can remove others, but users can remove themselves
    if team.owner_id != user.user().id && target_user_id != user.user().id {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "only the team owner can remove other members".to_owned(),
            }),
        )
            .into_response();
    }

    // Cannot remove the owner
    if target_user_id == team.owner_id {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "cannot remove the team owner".to_owned(),
            }),
        )
            .into_response();
    }

    match state
        .membership_repo
        .delete_by_team_and_user(team_id, target_user_id)
        .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(MessageResponse {
                message: "member removed successfully".to_owned(),
            }),
        )
            .into_response(),
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
        }
    }
}

pub async fn create_invitation<U, T, TM, MM, IM, CM>(
    State(state): State<TeamsState<U, T, TM, MM, IM, CM>>,
    user: TeamsAuthenticatedUser<U, T>,
    Path(team_id): Path<i32>,
    Json(body): Json<InviteMemberRequest>,
) -> impl IntoResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    TM: TeamRepository + Clone + Send + Sync + 'static,
    MM: TeamMembershipRepository + Clone + Send + Sync + 'static,
    IM: TeamInvitationRepository + Clone + Send + Sync + 'static,
    CM: Clone + Send + Sync + 'static,
{
    // Check if user is the owner
    match state.team_repo.find_by_id(team_id).await {
        Ok(Some(team)) => {
            if team.owner_id != user.user().id {
                return (
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "only the team owner can create invitations".to_owned(),
                    }),
                )
                    .into_response();
            }
        }
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "team not found".to_owned(),
                }),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::from(err)),
            )
                .into_response();
        }
    }

    // Generate invitation token
    let token = crypto::generate_token_default();
    let token_hash = crypto::hash_token(&token);

    let data = CreateInvitation {
        team_id,
        email: body.email,
        role: body.role,
        token_hash,
        invited_by: user.user().id,
        expires_at: Utc::now() + Duration::days(7),
    };

    match state.invitation_repo.create(data).await {
        Ok(invitation) => {
            // In a real application, you would send an email with the token here
            // For now, we return the invitation info (without the token for security)
            (
                StatusCode::CREATED,
                Json(TeamInvitationResponse::from(invitation)),
            )
                .into_response()
        }
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            (StatusCode::BAD_REQUEST, Json(error_response)).into_response()
        }
    }
}

pub async fn list_invitations<U, T, TM, MM, IM, CM>(
    State(state): State<TeamsState<U, T, TM, MM, IM, CM>>,
    user: TeamsAuthenticatedUser<U, T>,
    Path(team_id): Path<i32>,
) -> impl IntoResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    TM: TeamRepository + Clone + Send + Sync + 'static,
    MM: TeamMembershipRepository + Clone + Send + Sync + 'static,
    IM: TeamInvitationRepository + Clone + Send + Sync + 'static,
    CM: Clone + Send + Sync + 'static,
{
    // Check if user is the owner
    match state.team_repo.find_by_id(team_id).await {
        Ok(Some(team)) => {
            if team.owner_id != user.user().id {
                return (
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "only the team owner can view invitations".to_owned(),
                    }),
                )
                    .into_response();
            }
        }
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "team not found".to_owned(),
                }),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::from(err)),
            )
                .into_response();
        }
    }

    match state.invitation_repo.find_pending_by_team(team_id).await {
        Ok(invitations) => {
            let responses: Vec<_> = invitations
                .into_iter()
                .map(TeamInvitationResponse::from)
                .collect();
            Json(responses).into_response()
        }
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
        }
    }
}

pub async fn delete_invitation<U, T, TM, MM, IM, CM>(
    State(state): State<TeamsState<U, T, TM, MM, IM, CM>>,
    user: TeamsAuthenticatedUser<U, T>,
    Path((team_id, invitation_id)): Path<(i32, i32)>,
) -> impl IntoResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    TM: TeamRepository + Clone + Send + Sync + 'static,
    MM: TeamMembershipRepository + Clone + Send + Sync + 'static,
    IM: TeamInvitationRepository + Clone + Send + Sync + 'static,
    CM: Clone + Send + Sync + 'static,
{
    // Check if user is the owner
    match state.team_repo.find_by_id(team_id).await {
        Ok(Some(team)) => {
            if team.owner_id != user.user().id {
                return (
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "only the team owner can delete invitations".to_owned(),
                    }),
                )
                    .into_response();
            }
        }
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "team not found".to_owned(),
                }),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::from(err)),
            )
                .into_response();
        }
    }

    // Verify invitation belongs to this team
    match state.invitation_repo.find_by_id(invitation_id).await {
        Ok(Some(inv)) => {
            if inv.team_id != team_id {
                return (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "invitation not found".to_owned(),
                    }),
                )
                    .into_response();
            }
        }
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "invitation not found".to_owned(),
                }),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::from(err)),
            )
                .into_response();
        }
    }

    match state.invitation_repo.delete(invitation_id).await {
        Ok(()) => (
            StatusCode::OK,
            Json(MessageResponse {
                message: "invitation deleted successfully".to_owned(),
            }),
        )
            .into_response(),
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
        }
    }
}

pub async fn accept_invitation<U, T, TM, MM, IM, CM>(
    State(state): State<TeamsState<U, T, TM, MM, IM, CM>>,
    user: TeamsAuthenticatedUser<U, T>,
    Json(body): Json<AcceptInvitationRequest>,
) -> impl IntoResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    TM: TeamRepository + Clone + Send + Sync + 'static,
    MM: TeamMembershipRepository + Clone + Send + Sync + 'static,
    IM: TeamInvitationRepository + Clone + Send + Sync + 'static,
    CM: Clone + Send + Sync + 'static,
{
    let token_hash = crypto::hash_token(&body.token);

    // Find the invitation
    let invitation = match state.invitation_repo.find_by_token_hash(&token_hash).await {
        Ok(Some(inv)) => inv,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "invitation not found".to_owned(),
                }),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::from(err)),
            )
                .into_response();
        }
    };

    // Check if invitation is for this user's email
    if invitation.email != user.user().email {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "invitation is for a different email address".to_owned(),
            }),
        )
            .into_response();
    }

    // Check if invitation is expired
    if invitation.is_expired() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invitation has expired".to_owned(),
            }),
        )
            .into_response();
    }

    // Check if invitation is already accepted
    if invitation.is_accepted() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invitation has already been accepted".to_owned(),
            }),
        )
            .into_response();
    }

    // Check if user is already a member
    match state
        .membership_repo
        .find_by_team_and_user(invitation.team_id, user.user().id)
        .await
    {
        Ok(Some(_)) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "you are already a member of this team".to_owned(),
                }),
            )
                .into_response();
        }
        Ok(None) => {}
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::from(err)),
            )
                .into_response();
        }
    }

    // Create membership
    let data = CreateMembership {
        team_id: invitation.team_id,
        user_id: user.user().id,
        role: invitation.role.clone(),
    };

    let membership = match state.membership_repo.create(data).await {
        Ok(m) => m,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::from(err)),
            )
                .into_response();
        }
    };

    // Mark invitation as accepted
    if let Err(e) = state.invitation_repo.mark_accepted(invitation.id).await {
        log::error!(target: "enclave_auth", "msg=\"failed to mark invitation as accepted\", error=\"{e}\"");
    }

    (
        StatusCode::OK,
        Json(TeamMembershipResponse::from(membership)),
    )
        .into_response()
}

pub async fn get_current_team<U, T, TM, MM, IM, CM>(
    State(state): State<TeamsState<U, T, TM, MM, IM, CM>>,
    user: TeamsAuthenticatedUser<U, T>,
) -> impl IntoResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    TM: TeamRepository + Clone + Send + Sync + 'static,
    MM: TeamMembershipRepository + Clone + Send + Sync + 'static,
    IM: Clone + Send + Sync + 'static,
    CM: UserTeamContextRepository + Clone + Send + Sync + 'static,
{
    match state.context_repo.get_context(user.user().id).await {
        Ok(Some(ctx)) => {
            // Also fetch the team details
            match state.team_repo.find_by_id(ctx.current_team_id).await {
                Ok(Some(team)) => Json(serde_json::json!({
                    "context": UserTeamContextResponse::from(ctx),
                    "team": TeamResponse::from(team)
                }))
                .into_response(),
                Ok(None) => {
                    // Team was deleted, clear context
                    let _ = state.context_repo.clear_context(user.user().id).await;
                    (
                        StatusCode::NOT_FOUND,
                        Json(ErrorResponse {
                            error: "no current team set".to_owned(),
                        }),
                    )
                        .into_response()
                }
                Err(err) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse::from(err)),
                )
                    .into_response(),
            }
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "no current team set".to_owned(),
            }),
        )
            .into_response(),
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
        }
    }
}

pub async fn set_current_team<U, T, TM, MM, IM, CM>(
    State(state): State<TeamsState<U, T, TM, MM, IM, CM>>,
    user: TeamsAuthenticatedUser<U, T>,
    Json(body): Json<SetCurrentTeamRequest>,
) -> impl IntoResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    TM: TeamRepository + Clone + Send + Sync + 'static,
    MM: TeamMembershipRepository + Clone + Send + Sync + 'static,
    IM: Clone + Send + Sync + 'static,
    CM: UserTeamContextRepository + Clone + Send + Sync + 'static,
{
    // Check if user is a member of the team
    match state
        .membership_repo
        .find_by_team_and_user(body.team_id, user.user().id)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "you are not a member of this team".to_owned(),
                }),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::from(err)),
            )
                .into_response();
        }
    }

    match state
        .context_repo
        .set_current_team(user.user().id, body.team_id)
        .await
    {
        Ok(ctx) => Json(UserTeamContextResponse::from(ctx)).into_response(),
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
        }
    }
}

pub async fn clear_current_team<U, T, TM, MM, IM, CM>(
    State(state): State<TeamsState<U, T, TM, MM, IM, CM>>,
    user: TeamsAuthenticatedUser<U, T>,
) -> impl IntoResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    TM: Clone + Send + Sync + 'static,
    MM: Clone + Send + Sync + 'static,
    IM: Clone + Send + Sync + 'static,
    CM: UserTeamContextRepository + Clone + Send + Sync + 'static,
{
    match state.context_repo.clear_context(user.user().id).await {
        Ok(()) => (
            StatusCode::OK,
            Json(MessageResponse {
                message: "team context cleared".to_owned(),
            }),
        )
            .into_response(),
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
        }
    }
}
