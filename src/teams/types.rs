//! Core types for team management.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A team is an organizational unit that groups users together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Team {
    /// Unique identifier.
    pub id: i32,
    /// Human-readable team name.
    pub name: String,
    /// URL-friendly unique identifier.
    pub slug: String,
    /// User ID of the team owner.
    pub owner_id: i32,
    /// When the team was created.
    pub created_at: DateTime<Utc>,
    /// When the team was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Links a user to a team with a role.
///
/// The role is stored as a string in the database and parsed
/// using the user-defined `Role` trait implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamMembership {
    /// Unique identifier.
    pub id: i32,
    /// The team this membership belongs to.
    pub team_id: i32,
    /// The user who is a member.
    pub user_id: i32,
    /// The role as a string (parsed via `Role::from_str`).
    pub role: String,
    /// When the user joined the team.
    pub created_at: DateTime<Utc>,
    /// When the membership was last updated.
    pub updated_at: DateTime<Utc>,
}

impl TeamMembership {
    /// Parse the role string into a typed Role.
    ///
    /// Returns `None` if the role string is not recognized.
    pub fn parse_role<R: super::Role>(&self) -> Option<R> {
        R::from_str(&self.role)
    }
}

/// An invitation for a user to join a team.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamInvitation {
    /// Unique identifier.
    pub id: i32,
    /// The team being invited to.
    pub team_id: i32,
    /// Email of the invitee.
    pub email: String,
    /// Role to assign when accepted (as string).
    pub role: String,
    /// SHA-256 hash of the invitation token.
    #[serde(skip_serializing)]
    pub token_hash: String,
    /// User ID of who sent the invitation.
    pub invited_by: i32,
    /// When the invitation expires.
    pub expires_at: DateTime<Utc>,
    /// When the invitation was accepted (if accepted).
    pub accepted_at: Option<DateTime<Utc>>,
    /// When the invitation was created.
    pub created_at: DateTime<Utc>,
}

impl TeamInvitation {
    /// Parse the role string into a typed Role.
    pub fn parse_role<R: super::Role>(&self) -> Option<R> {
        R::from_str(&self.role)
    }

    /// Check if the invitation has expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }

    /// Check if the invitation has been accepted.
    pub fn is_accepted(&self) -> bool {
        self.accepted_at.is_some()
    }
}

/// Tracks a user's currently selected team.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserTeamContext {
    /// The user ID.
    pub user_id: i32,
    /// The currently selected team ID.
    pub current_team_id: i32,
    /// When this context was last updated.
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, PartialEq, Debug)]
    enum TestRole {
        Owner,
        Member,
    }

    impl super::super::Role for TestRole {
        fn as_str(&self) -> &'static str {
            match self {
                Self::Owner => "owner",
                Self::Member => "member",
            }
        }

        fn from_str(s: &str) -> Option<Self> {
            match s {
                "owner" => Some(Self::Owner),
                "member" => Some(Self::Member),
                _ => None,
            }
        }
    }

    #[test]
    fn test_membership_parse_role() {
        let membership = TeamMembership {
            id: 1,
            team_id: 1,
            user_id: 1,
            role: "owner".to_owned(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let role: Option<TestRole> = membership.parse_role();
        assert_eq!(role, Some(TestRole::Owner));
    }

    #[test]
    fn test_membership_parse_invalid_role() {
        let membership = TeamMembership {
            id: 1,
            team_id: 1,
            user_id: 1,
            role: "invalid".to_owned(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let role: Option<TestRole> = membership.parse_role();
        assert!(role.is_none());
    }

    #[test]
    fn test_invitation_is_expired() {
        let expired = TeamInvitation {
            id: 1,
            team_id: 1,
            email: "test@example.com".to_owned(),
            role: "member".to_owned(),
            token_hash: "hash".to_owned(),
            invited_by: 1,
            expires_at: Utc::now() - chrono::Duration::hours(1),
            accepted_at: None,
            created_at: Utc::now(),
        };

        assert!(expired.is_expired());

        let valid = TeamInvitation {
            expires_at: Utc::now() + chrono::Duration::hours(1),
            ..expired
        };

        assert!(!valid.is_expired());
    }
}
