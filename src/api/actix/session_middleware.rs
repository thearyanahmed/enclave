//! Session authentication middleware.

use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;

use actix_web::dev::Payload;
use actix_web::{FromRequest, HttpRequest, web};
use chrono::Utc;

use super::middleware::AuthenticationError;
use crate::AuthError;
use crate::session::{Session, SessionConfig, SessionRepository, verify_signed_cookie};

/// Authenticated user extractor for session-based authentication.
///
/// Use this in handler parameters to require session authentication.
/// The extractor validates the signed session cookie and retrieves
/// the session data from the repository.
#[derive(Debug, Clone)]
pub struct SessionAuthenticatedUser<S>
where
    S: SessionRepository,
{
    session: Session,
    _marker: PhantomData<S>,
}

impl<S> SessionAuthenticatedUser<S>
where
    S: SessionRepository,
{
    /// Returns the user ID from the session.
    pub fn user_id(&self) -> i32 {
        self.session.data.user_id
    }

    /// Returns the user's email from the session.
    pub fn email(&self) -> &str {
        &self.session.data.email
    }

    /// Returns the user's name from the session.
    pub fn name(&self) -> &str {
        &self.session.data.name
    }

    /// Returns a reference to the session.
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// Returns the inner session, consuming the wrapper.
    pub fn into_inner(self) -> Session {
        self.session
    }
}

/// Extracts the session cookie value from the request.
fn extract_session_cookie(req: &HttpRequest, config: &SessionConfig) -> Option<String> {
    req.cookie(&config.cookie_name)
        .map(|c| c.value().to_owned())
}

impl<S> FromRequest for SessionAuthenticatedUser<S>
where
    S: SessionRepository + Clone + 'static,
{
    type Error = AuthenticationError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let session_config = req.app_data::<web::Data<SessionConfig>>().cloned();

        let session_repo = req.app_data::<web::Data<S>>().cloned();

        let cookie_value = session_config
            .as_ref()
            .and_then(|config| extract_session_cookie(req, config));

        Box::pin(async move {
            let session_config = session_config.ok_or_else(|| AuthenticationError {
                error: AuthError::ConfigurationError("SessionConfig not found".to_owned()),
            })?;

            let session_repo = session_repo.ok_or_else(|| AuthenticationError {
                error: AuthError::ConfigurationError("SessionRepository not found".to_owned()),
            })?;

            let cookie_value = cookie_value.ok_or(AuthenticationError {
                error: AuthError::TokenInvalid,
            })?;

            // Verify the HMAC signature
            let session_id = verify_signed_cookie(&cookie_value, &session_config.secret_key)
                .ok_or_else(|| {
                    log::warn!(target: "enclave_auth::session", "msg=\"session cookie verification failed\"");
                    AuthenticationError {
                        error: AuthError::TokenInvalid,
                    }
                })?;

            // Look up the session
            let session = session_repo
                .find(&session_id)
                .await
                .map_err(|e| AuthenticationError { error: e })?
                .ok_or(AuthenticationError {
                    error: AuthError::TokenInvalid,
                })?;

            // Check expiry
            if session.is_expired() {
                // Clean up expired session
                let _ = session_repo.destroy(&session_id).await;
                return Err(AuthenticationError {
                    error: AuthError::TokenExpired,
                });
            }

            // Extend session (sliding window)
            let new_expires_at = Utc::now() + session_config.session_lifetime;
            if let Err(e) = session_repo.extend(&session_id, new_expires_at).await {
                log::warn!(target: "enclave_auth::session", "msg=\"failed to extend session\" error=\"{e}\"");
            }

            Ok(SessionAuthenticatedUser {
                session,
                _marker: PhantomData,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_authenticated_user_accessors() {
        use chrono::Duration;

        use crate::session::SessionData;

        let data = SessionData {
            user_id: 42,
            email: "test@example.com".to_owned(),
            name: "Test User".to_owned(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(2),
        };

        let session = Session::new("session123".to_owned(), data);
        let auth_user: SessionAuthenticatedUser<crate::session::InMemorySessionRepository> =
            SessionAuthenticatedUser {
                session,
                _marker: PhantomData,
            };

        assert_eq!(auth_user.user_id(), 42);
        assert_eq!(auth_user.email(), "test@example.com");
        assert_eq!(auth_user.name(), "Test User");
    }
}
