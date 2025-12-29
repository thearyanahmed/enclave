use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::SecretString;

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub name: String,
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

#[cfg(feature = "magic_link")]
#[derive(Debug, Deserialize)]
pub struct MagicLinkRequest {
    pub email: String,
}

#[cfg(feature = "magic_link")]
#[derive(Debug, Deserialize)]
pub struct VerifyMagicLinkRequest {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: u64,
    pub email: String,
    pub name: String,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub user: UserResponse,
    pub token: SecretString,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for AuthResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthResponse")
            .field("user", &self.user)
            .field("token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub token: SecretString,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl From<crate::AuthUser> for UserResponse {
    fn from(user: crate::AuthUser) -> Self {
        UserResponse {
            id: user.id,
            email: user.email,
            name: user.name,
            email_verified_at: user.email_verified_at,
            created_at: user.created_at,
        }
    }
}

impl From<crate::AuthError> for ErrorResponse {
    #[allow(deprecated)]
    fn from(err: crate::AuthError) -> Self {
        // Sanitize internal errors to prevent information leakage
        let error = match &err {
            crate::AuthError::DatabaseError(_)
            | crate::AuthError::ConfigurationError(_)
            | crate::AuthError::Other(_) => "an internal error occurred".to_owned(),
            _ => err.to_string().to_lowercase(),
        };

        ErrorResponse { error }
    }
}

#[cfg(feature = "teams")]
#[derive(Debug, Deserialize)]
pub struct CreateTeamRequest {
    pub name: String,
    pub slug: String,
}

#[cfg(feature = "teams")]
#[derive(Debug, Deserialize)]
pub struct UpdateTeamRequest {
    pub name: Option<String>,
    pub slug: Option<String>,
}

#[cfg(feature = "teams")]
#[derive(Debug, Deserialize)]
pub struct TransferOwnershipRequest {
    pub new_owner_id: u64,
}

#[cfg(feature = "teams")]
#[derive(Debug, Deserialize)]
pub struct AddMemberRequest {
    pub user_id: u64,
    pub role: String,
}

#[cfg(feature = "teams")]
#[derive(Debug, Deserialize)]
pub struct InviteMemberRequest {
    pub email: String,
    pub role: String,
}

#[cfg(feature = "teams")]
#[derive(Debug, Deserialize)]
pub struct UpdateMemberRoleRequest {
    pub role: String,
}

#[cfg(feature = "teams")]
#[derive(Debug, Deserialize)]
pub struct AcceptInvitationRequest {
    pub token: String,
}

#[cfg(feature = "teams")]
#[derive(Debug, Deserialize)]
pub struct SetCurrentTeamRequest {
    pub team_id: u64,
}

#[cfg(feature = "teams")]
#[derive(Debug, Serialize)]
pub struct TeamResponse {
    pub id: u64,
    pub name: String,
    pub slug: String,
    pub owner_id: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[cfg(feature = "teams")]
impl From<crate::teams::Team> for TeamResponse {
    fn from(team: crate::teams::Team) -> Self {
        TeamResponse {
            id: team.id,
            name: team.name,
            slug: team.slug,
            owner_id: team.owner_id,
            created_at: team.created_at,
            updated_at: team.updated_at,
        }
    }
}

#[cfg(feature = "teams")]
#[derive(Debug, Serialize)]
pub struct TeamMembershipResponse {
    pub id: u64,
    pub team_id: u64,
    pub user_id: u64,
    pub role: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[cfg(feature = "teams")]
impl From<crate::teams::TeamMembership> for TeamMembershipResponse {
    fn from(m: crate::teams::TeamMembership) -> Self {
        TeamMembershipResponse {
            id: m.id,
            team_id: m.team_id,
            user_id: m.user_id,
            role: m.role,
            created_at: m.created_at,
            updated_at: m.updated_at,
        }
    }
}

#[cfg(feature = "teams")]
#[derive(Debug, Serialize)]
pub struct TeamInvitationResponse {
    pub id: u64,
    pub team_id: u64,
    pub email: String,
    pub role: String,
    pub invited_by: u64,
    pub expires_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[cfg(feature = "teams")]
impl From<crate::teams::TeamInvitation> for TeamInvitationResponse {
    fn from(inv: crate::teams::TeamInvitation) -> Self {
        TeamInvitationResponse {
            id: inv.id,
            team_id: inv.team_id,
            email: inv.email,
            role: inv.role,
            invited_by: inv.invited_by,
            expires_at: inv.expires_at,
            accepted_at: inv.accepted_at,
            created_at: inv.created_at,
        }
    }
}

#[cfg(feature = "teams")]
#[derive(Debug, Serialize)]
pub struct UserTeamContextResponse {
    pub user_id: u64,
    pub current_team_id: u64,
    pub updated_at: DateTime<Utc>,
}

#[cfg(feature = "teams")]
impl From<crate::teams::UserTeamContext> for UserTeamContextResponse {
    fn from(ctx: crate::teams::UserTeamContext) -> Self {
        UserTeamContextResponse {
            user_id: ctx.user_id,
            current_team_id: ctx.current_team_id,
            updated_at: ctx.updated_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_error_is_sanitized() {
        let err =
            crate::AuthError::DatabaseError("ERROR: relation \"users\" does not exist".to_owned());
        let response: ErrorResponse = err.into();

        assert_eq!(response.error, "an internal error occurred");
        assert!(!response.error.contains("users"));
        assert!(!response.error.contains("relation"));
    }

    #[test]
    fn test_configuration_error_is_sanitized() {
        let err = crate::AuthError::ConfigurationError("secret key: abc123xyz".to_owned());
        let response: ErrorResponse = err.into();

        assert_eq!(response.error, "an internal error occurred");
        assert!(!response.error.contains("abc123xyz"));
    }

    #[test]
    #[allow(deprecated)]
    fn test_other_error_is_sanitized() {
        let err = crate::AuthError::Other("internal stack trace here".to_owned());
        let response: ErrorResponse = err.into();

        assert_eq!(response.error, "an internal error occurred");
        assert!(!response.error.contains("stack trace"));
    }

    #[test]
    fn test_user_facing_errors_are_lowercase() {
        let test_cases = [
            (crate::AuthError::UserNotFound, "user not found"),
            (crate::AuthError::UserAlreadyExists, "user already exists"),
            (
                crate::AuthError::InvalidCredentials,
                "invalid email or password",
            ),
            (crate::AuthError::TokenExpired, "token has expired"),
            (crate::AuthError::TokenInvalid, "invalid token"),
        ];

        for (err, expected_message) in test_cases {
            let response: ErrorResponse = err.into();
            assert_eq!(response.error, expected_message);
        }
    }
}
