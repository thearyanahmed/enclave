use crate::crypto::hash_token;
use crate::teams::{
    CreateMembership, TeamInvitationRepository, TeamMembership, TeamMembershipRepository,
};
use crate::{AuthError, SecretString, UserRepository};

/// Action to accept a team invitation.
///
/// This action:
/// 1. Validates the token
/// 2. Verifies the invitation belongs to the user's email
/// 3. Checks invitation is not expired or already accepted
/// 4. Creates the team membership
/// 5. Marks the invitation as accepted
///
/// The user must provide the plain token (received via email).
#[allow(clippy::struct_field_names)]
pub struct AcceptInvitationAction<I, M, U>
where
    I: TeamInvitationRepository,
    M: TeamMembershipRepository,
    U: UserRepository,
{
    invitation_repo: I,
    membership_repo: M,
    user_repo: U,
}

impl<I, M, U> AcceptInvitationAction<I, M, U>
where
    I: TeamInvitationRepository,
    M: TeamMembershipRepository,
    U: UserRepository,
{
    /// Creates a new `AcceptInvitationAction`.
    pub fn new(invitation_repo: I, membership_repo: M, user_repo: U) -> Self {
        Self {
            invitation_repo,
            membership_repo,
            user_repo,
        }
    }

    /// Accepts a team invitation using the provided token.
    ///
    /// # Arguments
    ///
    /// * `token` - The invitation token (plain text, as sent to invitee)
    /// * `user_id` - The ID of the user accepting the invitation
    ///
    /// # Returns
    ///
    /// - `Ok(membership)` - Invitation accepted, user added to team
    /// - `Err(AuthError::TokenInvalid)` - Token not found
    /// - `Err(AuthError::TokenExpired)` - Invitation has expired
    /// - `Err(AuthError::EmailMismatch)` - User's email doesn't match invitation
    /// - `Err(AuthError::InvitationAlreadyAccepted)` - Invitation already used
    /// - `Err(AuthError::AlreadyMember)` - User already in team
    /// - `Err(_)` - Database or other errors
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "accept_invitation", skip_all, err)
    )]
    pub async fn execute(
        &self,
        token: &SecretString,
        user_id: i64,
    ) -> Result<TeamMembership, AuthError> {
        // hash the token to find it
        let token_hash = hash_token(token.expose_secret());

        // find invitation
        let invitation = self
            .invitation_repo
            .find_by_token_hash(&token_hash)
            .await?
            .ok_or(AuthError::TokenInvalid)?;

        // get the user to verify email
        let user = self
            .user_repo
            .find_user_by_id(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        // verify email matches
        if invitation.email != user.email {
            return Err(AuthError::EmailMismatch);
        }

        // check not expired
        if invitation.is_expired() {
            return Err(AuthError::TokenExpired);
        }

        // check not already accepted
        if invitation.is_accepted() {
            return Err(AuthError::InvitationAlreadyAccepted);
        }

        // check user is not already a member
        if self
            .membership_repo
            .find_by_team_and_user(invitation.team_id, user_id)
            .await?
            .is_some()
        {
            return Err(AuthError::AlreadyMember);
        }

        // create membership
        let membership_data = CreateMembership {
            team_id: invitation.team_id,
            user_id,
            role: invitation.role.clone(),
        };

        let membership = self.membership_repo.create(membership_data).await?;

        // mark invitation as accepted (log error but don't fail)
        if let Err(e) = self.invitation_repo.mark_accepted(invitation.id).await {
            log::error!(
                target: "enclave_auth",
                "msg=\"failed to mark invitation as accepted\", invitation_id={}, error=\"{e}\"",
                invitation.id
            );
        }

        log::info!(
            target: "enclave_auth",
            "msg=\"invitation accepted\", team_id={}, user_id={}, membership_id={}",
            membership.team_id,
            membership.user_id,
            membership.id
        );

        Ok(membership)
    }
}

#[cfg(all(test, feature = "mocks"))]
mod tests {
    use chrono::{Duration, Utc};

    use super::*;
    use crate::teams::{
        CreateInvitation, CreateTeam, MockTeamInvitationRepository, MockTeamMembershipRepository,
        MockTeamRepository, TeamRepository,
    };
    use crate::{AuthUser, MockUserRepository};

    fn create_test_user(id: i64, email: &str) -> AuthUser {
        AuthUser {
            id,
            email: email.to_owned(),
            name: "Test User".to_owned(),
            hashed_password: "hash".to_owned(),
            email_verified_at: Some(Utc::now()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_accept_success() {
        let team_repo = MockTeamRepository::new();
        let invitation_repo = MockTeamInvitationRepository::new();
        let membership_repo = MockTeamMembershipRepository::new();
        let user_repo = MockUserRepository::new();

        // setup: create team
        let team = team_repo
            .create(CreateTeam {
                name: "Test Team".to_owned(),
                slug: "test-team".to_owned(),
                owner_id: 1,
            })
            .await
            .unwrap();

        // setup: create user
        let user = create_test_user(2, "invitee@example.com");
        user_repo.users.lock().unwrap().push(user);

        // setup: create invitation with known token hash
        let token = "test-token-12345";
        let token_hash = crate::crypto::hash_token(token);
        let invitation = invitation_repo
            .create(CreateInvitation {
                team_id: team.id,
                email: "invitee@example.com".to_owned(),
                role: "member".to_owned(),
                token_hash,
                invited_by: 1,
                expires_at: Utc::now() + Duration::days(7),
            })
            .await
            .unwrap();

        let action = AcceptInvitationAction::new(invitation_repo, membership_repo, user_repo);

        let result = action
            .execute(&SecretString::new(token.to_owned()), 2)
            .await;

        assert!(result.is_ok());
        let membership = result.unwrap();
        assert_eq!(membership.team_id, invitation.team_id);
        assert_eq!(membership.user_id, 2);
        assert_eq!(membership.role, "member");
    }

    #[tokio::test]
    async fn test_accept_invalid_token() {
        let invitation_repo = MockTeamInvitationRepository::new();
        let membership_repo = MockTeamMembershipRepository::new();
        let user_repo = MockUserRepository::new();

        let action = AcceptInvitationAction::new(invitation_repo, membership_repo, user_repo);

        let result = action
            .execute(&SecretString::new("invalid-token".to_owned()), 1)
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::TokenInvalid));
    }

    #[tokio::test]
    async fn test_accept_email_mismatch() {
        let team_repo = MockTeamRepository::new();
        let invitation_repo = MockTeamInvitationRepository::new();
        let membership_repo = MockTeamMembershipRepository::new();
        let user_repo = MockUserRepository::new();

        // setup: create team
        let team = team_repo
            .create(CreateTeam {
                name: "Test Team".to_owned(),
                slug: "test-team".to_owned(),
                owner_id: 1,
            })
            .await
            .unwrap();

        // setup: create user with different email
        let user = create_test_user(2, "different@example.com");
        user_repo.users.lock().unwrap().push(user);

        // setup: create invitation for different email
        let token = "test-token-12345";
        let token_hash = crate::crypto::hash_token(token);
        invitation_repo
            .create(CreateInvitation {
                team_id: team.id,
                email: "invitee@example.com".to_owned(), // different from user's email
                role: "member".to_owned(),
                token_hash,
                invited_by: 1,
                expires_at: Utc::now() + Duration::days(7),
            })
            .await
            .unwrap();

        let action = AcceptInvitationAction::new(invitation_repo, membership_repo, user_repo);

        let result = action
            .execute(&SecretString::new(token.to_owned()), 2)
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::EmailMismatch));
    }

    #[tokio::test]
    async fn test_accept_expired() {
        let team_repo = MockTeamRepository::new();
        let invitation_repo = MockTeamInvitationRepository::new();
        let membership_repo = MockTeamMembershipRepository::new();
        let user_repo = MockUserRepository::new();

        // setup: create team
        let team = team_repo
            .create(CreateTeam {
                name: "Test Team".to_owned(),
                slug: "test-team".to_owned(),
                owner_id: 1,
            })
            .await
            .unwrap();

        // setup: create user
        let user = create_test_user(2, "invitee@example.com");
        user_repo.users.lock().unwrap().push(user);

        // setup: create expired invitation
        let token = "test-token-12345";
        let token_hash = crate::crypto::hash_token(token);
        invitation_repo
            .create(CreateInvitation {
                team_id: team.id,
                email: "invitee@example.com".to_owned(),
                role: "member".to_owned(),
                token_hash,
                invited_by: 1,
                expires_at: Utc::now() - Duration::hours(1), // already expired
            })
            .await
            .unwrap();

        let action = AcceptInvitationAction::new(invitation_repo, membership_repo, user_repo);

        let result = action
            .execute(&SecretString::new(token.to_owned()), 2)
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::TokenExpired));
    }

    #[tokio::test]
    async fn test_accept_already_member() {
        let team_repo = MockTeamRepository::new();
        let invitation_repo = MockTeamInvitationRepository::new();
        let membership_repo = MockTeamMembershipRepository::new();
        let user_repo = MockUserRepository::new();

        // setup: create team
        let team = team_repo
            .create(CreateTeam {
                name: "Test Team".to_owned(),
                slug: "test-team".to_owned(),
                owner_id: 1,
            })
            .await
            .unwrap();

        // setup: create user
        let user = create_test_user(2, "invitee@example.com");
        user_repo.users.lock().unwrap().push(user);

        // setup: user is already a member
        membership_repo
            .create(CreateMembership {
                team_id: team.id,
                user_id: 2,
                role: "member".to_owned(),
            })
            .await
            .unwrap();

        // setup: create invitation
        let token = "test-token-12345";
        let token_hash = crate::crypto::hash_token(token);
        invitation_repo
            .create(CreateInvitation {
                team_id: team.id,
                email: "invitee@example.com".to_owned(),
                role: "member".to_owned(),
                token_hash,
                invited_by: 1,
                expires_at: Utc::now() + Duration::days(7),
            })
            .await
            .unwrap();

        let action = AcceptInvitationAction::new(invitation_repo, membership_repo, user_repo);

        let result = action
            .execute(&SecretString::new(token.to_owned()), 2)
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::AlreadyMember));
    }
}
