use chrono::{DateTime, Utc};

/// Authentication events emitted by enclave actions.
///
/// Events are always fired from actions. If no listeners are registered,
/// they are silently ignored (no-op). Register listeners via
/// [`register_event_listeners`](crate::register_event_listeners) to handle events.
#[derive(Debug, Clone)]
pub enum AuthEvent {
    // user lifecycle
    UserRegistered {
        user_id: i64,
        email: String,
        at: DateTime<Utc>,
    },
    UserDeleted {
        user_id: i64,
        at: DateTime<Utc>,
    },

    // authentication
    LoginSuccess {
        user_id: i64,
        email: String,
        at: DateTime<Utc>,
    },
    LoginFailed {
        email: String,
        reason: String,
        at: DateTime<Utc>,
    },
    LogoutSuccess {
        user_id: i64,
        at: DateTime<Utc>,
    },

    // password
    PasswordChanged {
        user_id: i64,
        at: DateTime<Utc>,
    },
    PasswordResetRequested {
        email: String,
        at: DateTime<Utc>,
    },
    PasswordResetCompleted {
        user_id: i64,
        at: DateTime<Utc>,
    },

    // email
    EmailVerificationSent {
        user_id: i64,
        email: String,
        at: DateTime<Utc>,
    },
    EmailVerified {
        user_id: i64,
        at: DateTime<Utc>,
    },

    // token
    TokenRefreshed {
        user_id: i64,
        at: DateTime<Utc>,
    },
    AllTokensRevoked {
        user_id: i64,
        at: DateTime<Utc>,
    },
}

impl AuthEvent {
    /// Returns a dot-separated event name for logging/tracing.
    pub fn name(&self) -> &'static str {
        match self {
            Self::UserRegistered { .. } => "user.registered",
            Self::UserDeleted { .. } => "user.deleted",
            Self::LoginSuccess { .. } => "auth.login.success",
            Self::LoginFailed { .. } => "auth.login.failed",
            Self::LogoutSuccess { .. } => "auth.logout.success",
            Self::PasswordChanged { .. } => "auth.password.changed",
            Self::PasswordResetRequested { .. } => "auth.password.reset_requested",
            Self::PasswordResetCompleted { .. } => "auth.password.reset_completed",
            Self::EmailVerificationSent { .. } => "auth.email.verification_sent",
            Self::EmailVerified { .. } => "auth.email.verified",
            Self::TokenRefreshed { .. } => "auth.token.refreshed",
            Self::AllTokensRevoked { .. } => "auth.token.all_revoked",
        }
    }

    /// Returns the timestamp when this event occurred.
    pub fn timestamp(&self) -> DateTime<Utc> {
        match self {
            Self::UserRegistered { at, .. }
            | Self::UserDeleted { at, .. }
            | Self::LoginSuccess { at, .. }
            | Self::LoginFailed { at, .. }
            | Self::LogoutSuccess { at, .. }
            | Self::PasswordChanged { at, .. }
            | Self::PasswordResetRequested { at, .. }
            | Self::PasswordResetCompleted { at, .. }
            | Self::EmailVerificationSent { at, .. }
            | Self::EmailVerified { at, .. }
            | Self::TokenRefreshed { at, .. }
            | Self::AllTokensRevoked { at, .. } => *at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_names() {
        let now = Utc::now();

        assert_eq!(
            AuthEvent::UserRegistered {
                user_id: 1,
                email: "test@example.com".to_owned(),
                at: now
            }
            .name(),
            "user.registered"
        );

        assert_eq!(
            AuthEvent::UserDeleted {
                user_id: 1,
                at: now
            }
            .name(),
            "user.deleted"
        );

        assert_eq!(
            AuthEvent::LoginSuccess {
                user_id: 1,
                email: "test@example.com".to_owned(),
                at: now
            }
            .name(),
            "auth.login.success"
        );

        assert_eq!(
            AuthEvent::LoginFailed {
                email: "test@example.com".to_owned(),
                reason: "invalid password".to_owned(),
                at: now
            }
            .name(),
            "auth.login.failed"
        );

        assert_eq!(
            AuthEvent::LogoutSuccess {
                user_id: 1,
                at: now
            }
            .name(),
            "auth.logout.success"
        );

        assert_eq!(
            AuthEvent::PasswordChanged {
                user_id: 1,
                at: now
            }
            .name(),
            "auth.password.changed"
        );

        assert_eq!(
            AuthEvent::PasswordResetRequested {
                email: "test@example.com".to_owned(),
                at: now
            }
            .name(),
            "auth.password.reset_requested"
        );

        assert_eq!(
            AuthEvent::PasswordResetCompleted {
                user_id: 1,
                at: now
            }
            .name(),
            "auth.password.reset_completed"
        );

        assert_eq!(
            AuthEvent::EmailVerificationSent {
                user_id: 1,
                email: "test@example.com".to_owned(),
                at: now
            }
            .name(),
            "auth.email.verification_sent"
        );

        assert_eq!(
            AuthEvent::EmailVerified {
                user_id: 1,
                at: now
            }
            .name(),
            "auth.email.verified"
        );

        assert_eq!(
            AuthEvent::TokenRefreshed {
                user_id: 1,
                at: now
            }
            .name(),
            "auth.token.refreshed"
        );

        assert_eq!(
            AuthEvent::AllTokensRevoked {
                user_id: 1,
                at: now
            }
            .name(),
            "auth.token.all_revoked"
        );
    }

    #[test]
    fn test_event_timestamp() {
        let now = Utc::now();

        let event = AuthEvent::LoginSuccess {
            user_id: 1,
            email: "test@example.com".to_owned(),
            at: now,
        };

        assert_eq!(event.timestamp(), now);
    }

    #[test]
    fn test_event_clone() {
        let now = Utc::now();
        let event = AuthEvent::UserRegistered {
            user_id: 1,
            email: "test@example.com".to_owned(),
            at: now,
        };

        let cloned = event.clone();
        assert_eq!(event.name(), cloned.name());
        assert_eq!(event.timestamp(), cloned.timestamp());
    }

    #[test]
    fn test_event_debug() {
        let now = Utc::now();
        let event = AuthEvent::LoginFailed {
            email: "test@example.com".to_owned(),
            reason: "invalid credentials".to_owned(),
            at: now,
        };

        let debug_str = format!("{event:?}");
        assert!(debug_str.contains("LoginFailed"));
        assert!(debug_str.contains("test@example.com"));
        assert!(debug_str.contains("invalid credentials"));
    }
}
