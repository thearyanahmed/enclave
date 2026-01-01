use chrono::{Duration, Utc};

use crate::crypto::{generate_token_default, hash_token};
use crate::teams::{CreateInvitation, TeamInvitation, TeamInvitationRepository, TeamRepository};
use crate::{AuthError, SecretString};

/// Configuration for team invitations.
#[derive(Debug, Clone)]
pub struct InvitationConfig {
    /// Number of days until invitation expires. Default: 7
    pub expiry_days: i64,
}

impl Default for InvitationConfig {
    fn default() -> Self {
        Self { expiry_days: 7 }
    }
}

/// Input data for creating a team invitation.
#[derive(Debug, Clone)]
pub struct InviteToTeamInput {
    pub team_id: i64,
    pub email: String,
    pub role: String,
    pub invited_by: i64,
}

/// Output from creating a team invitation.
#[derive(Debug)]
pub struct InviteToTeamOutput {
    /// The created invitation record.
    pub invitation: TeamInvitation,
    /// The plain token to send to the invitee (not stored, only returned once).
    pub token: SecretString,
}

/// Action to invite a user to a team.
///
/// This action:
/// 1. Validates the team exists
/// 2. Verifies the inviter is the team owner
/// 3. Generates a secure invitation token
/// 4. Creates the invitation record
///
/// The returned token should be sent to the invitee (e.g., via email).
/// The token is hashed before storage and cannot be retrieved later.
pub struct InviteToTeamAction<T, I>
where
    T: TeamRepository,
    I: TeamInvitationRepository,
{
    team_repo: T,
    invitation_repo: I,
    config: InvitationConfig,
}

impl<T: TeamRepository, I: TeamInvitationRepository> InviteToTeamAction<T, I> {
    /// Creates a new `InviteToTeamAction` with default configuration.
    pub fn new(team_repo: T, invitation_repo: I) -> Self {
        Self {
            team_repo,
            invitation_repo,
            config: InvitationConfig::default(),
        }
    }

    /// Creates a new `InviteToTeamAction` with custom configuration.
    pub fn with_config(team_repo: T, invitation_repo: I, config: InvitationConfig) -> Self {
        Self {
            team_repo,
            invitation_repo,
            config,
        }
    }

    /// Creates an invitation for a user to join a team.
    ///
    /// # Arguments
    ///
    /// * `input` - The invitation details (`team_id`, email, role, `invited_by`)
    ///
    /// # Returns
    ///
    /// - `Ok(output)` - Invitation created with plain token for delivery
    /// - `Err(AuthError::NotFound)` - Team does not exist
    /// - `Err(AuthError::Internal("forbidden: ..."))` - Inviter is not team owner
    /// - `Err(_)` - Database or other errors
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "invite_to_team", skip_all, err)
    )]
    pub async fn execute(&self, input: InviteToTeamInput) -> Result<InviteToTeamOutput, AuthError> {
        // validate team exists
        let team = self
            .team_repo
            .find_by_id(input.team_id)
            .await?
            .ok_or(AuthError::NotFound)?;

        // verify inviter is team owner
        if team.owner_id != input.invited_by {
            return Err(AuthError::Forbidden);
        }

        // generate token
        let token = generate_token_default();
        let token_hash = hash_token(&token);

        // calculate expiry
        let expires_at = Utc::now() + Duration::days(self.config.expiry_days);

        // create invitation
        let data = CreateInvitation {
            team_id: input.team_id,
            email: input.email,
            role: input.role,
            token_hash,
            invited_by: input.invited_by,
            expires_at,
        };

        let invitation = self.invitation_repo.create(data).await?;

        log::info!(
            target: "enclave_auth",
            "msg=\"invitation created\", team_id={}, invitation_id={}, email=\"{}\"",
            invitation.team_id,
            invitation.id,
            invitation.email
        );

        Ok(InviteToTeamOutput {
            invitation,
            token: SecretString::new(token),
        })
    }
}

#[cfg(all(test, feature = "mocks"))]
mod tests {
    use super::*;
    use crate::teams::{MockTeamInvitationRepository, MockTeamRepository};

    fn setup_repos() -> (MockTeamRepository, MockTeamInvitationRepository) {
        (
            MockTeamRepository::new(),
            MockTeamInvitationRepository::new(),
        )
    }

    #[tokio::test]
    async fn test_invite_success() {
        let (team_repo, invitation_repo) = setup_repos();

        // create a team with owner_id = 1
        let team = team_repo
            .create(crate::teams::CreateTeam {
                name: "Test Team".to_owned(),
                slug: "test-team".to_owned(),
                owner_id: 1,
            })
            .await
            .unwrap();

        let action = InviteToTeamAction::new(team_repo, invitation_repo);

        let input = InviteToTeamInput {
            team_id: team.id,
            email: "invitee@example.com".to_owned(),
            role: "member".to_owned(),
            invited_by: 1, // owner
        };

        let result = action.execute(input).await;
        assert!(result.is_ok());

        let output = result.unwrap();
        assert_eq!(output.invitation.email, "invitee@example.com");
        assert_eq!(output.invitation.role, "member");
        assert!(!output.token.expose_secret().is_empty());
    }

    #[tokio::test]
    async fn test_invite_team_not_found() {
        let (team_repo, invitation_repo) = setup_repos();
        let action = InviteToTeamAction::new(team_repo, invitation_repo);

        let input = InviteToTeamInput {
            team_id: 999, // non-existent
            email: "invitee@example.com".to_owned(),
            role: "member".to_owned(),
            invited_by: 1,
        };

        let result = action.execute(input).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::NotFound));
    }

    #[tokio::test]
    async fn test_invite_not_owner() {
        let (team_repo, invitation_repo) = setup_repos();

        // create a team with owner_id = 1
        let team = team_repo
            .create(crate::teams::CreateTeam {
                name: "Test Team".to_owned(),
                slug: "test-team".to_owned(),
                owner_id: 1,
            })
            .await
            .unwrap();

        let action = InviteToTeamAction::new(team_repo, invitation_repo);

        let input = InviteToTeamInput {
            team_id: team.id,
            email: "invitee@example.com".to_owned(),
            role: "member".to_owned(),
            invited_by: 2, // not the owner
        };

        let result = action.execute(input).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::Forbidden));
    }

    #[tokio::test]
    async fn test_invite_custom_expiry() {
        let (team_repo, invitation_repo) = setup_repos();

        let team = team_repo
            .create(crate::teams::CreateTeam {
                name: "Test Team".to_owned(),
                slug: "test-team".to_owned(),
                owner_id: 1,
            })
            .await
            .unwrap();

        let config = InvitationConfig { expiry_days: 14 };
        let action = InviteToTeamAction::with_config(team_repo, invitation_repo, config);

        let input = InviteToTeamInput {
            team_id: team.id,
            email: "invitee@example.com".to_owned(),
            role: "admin".to_owned(),
            invited_by: 1,
        };

        let result = action.execute(input).await;
        assert!(result.is_ok());

        let output = result.unwrap();
        // check expiry is approximately 14 days from now
        let expected_expiry = Utc::now() + Duration::days(14);
        let diff = (output.invitation.expires_at - expected_expiry)
            .num_seconds()
            .abs();
        assert!(diff < 5, "expiry should be ~14 days from now");
    }
}
