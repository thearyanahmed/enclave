use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Team {
    pub id: i32,
    pub name: String,
    pub slug: String,
    pub owner_id: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// role is stored as string, parse with `Role::from_str`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamMembership {
    pub id: i32,
    pub team_id: i32,
    pub user_id: i32,
    pub role: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl TeamMembership {
    pub fn parse_role<R: super::Role>(&self) -> Option<R> {
        R::from_str(&self.role)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamInvitation {
    pub id: i32,
    pub team_id: i32,
    pub email: String,
    pub role: String,
    #[serde(skip_serializing)]
    pub token_hash: String,
    pub invited_by: i32,
    pub expires_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl TeamInvitation {
    pub fn parse_role<R: super::Role>(&self) -> Option<R> {
        R::from_str(&self.role)
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }

    pub fn is_accepted(&self) -> bool {
        self.accepted_at.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserTeamContext {
    pub user_id: i32,
    pub current_team_id: i32,
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
