use actix_web::{FromRequest, HttpRequest, HttpResponse, dev::Payload, http::header, web};
use std::future::Future;
use std::pin::Pin;

use crate::{AuthError, AuthUser, TokenRepository, UserRepository};

/// Authenticated user extractor for actix-web handlers.
///
/// Use this in handler parameters to require authentication.
/// The extractor validates the bearer token from the `Authorization` header
/// and retrieves the associated user from the repository.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser<U, T>
where
    U: UserRepository,
    T: TokenRepository,
{
    user: AuthUser,
    _marker: std::marker::PhantomData<(U, T)>,
}

impl<U, T> AuthenticatedUser<U, T>
where
    U: UserRepository,
    T: TokenRepository,
{
    /// Returns the inner user, consuming the wrapper.
    pub fn into_inner(self) -> AuthUser {
        self.user
    }

    /// Returns a reference to the authenticated user.
    pub fn user(&self) -> &AuthUser {
        &self.user
    }
}

/// Error type for authentication failures.
#[derive(Debug)]
pub struct AuthenticationError {
    pub error: AuthError,
}

impl std::fmt::Display for AuthenticationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl actix_web::ResponseError for AuthenticationError {
    fn error_response(&self) -> HttpResponse {
        use crate::api::ErrorResponse;

        let error_response = ErrorResponse::from(self.error.clone());

        match &self.error {
            AuthError::TokenExpired | AuthError::TokenInvalid => {
                HttpResponse::Unauthorized().json(error_response)
            }
            _ => HttpResponse::InternalServerError().json(error_response),
        }
    }
}

/// Extracts the bearer token from the Authorization header.
pub fn extract_bearer_token(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()
        .and_then(|auth| auth.strip_prefix("Bearer "))
        .map(ToOwned::to_owned)
}

impl<U, T> FromRequest for AuthenticatedUser<U, T>
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
{
    type Error = AuthenticationError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let token = extract_bearer_token(req);

        let token_repo = req
            .app_data::<web::Data<T>>()
            .map(|data| data.get_ref().clone());

        let user_repo = req
            .app_data::<web::Data<U>>()
            .map(|data| data.get_ref().clone());

        Box::pin(async move {
            let token = token.ok_or(AuthenticationError {
                error: AuthError::TokenInvalid,
            })?;

            let token_repo = token_repo.ok_or(AuthenticationError {
                error: AuthError::TokenInvalid,
            })?;

            let user_repo = user_repo.ok_or(AuthenticationError {
                error: AuthError::TokenInvalid,
            })?;

            // find_token handles hashing internally
            let access_token = token_repo
                .find_token(&token)
                .await
                .map_err(|e| AuthenticationError { error: e })?
                .ok_or(AuthenticationError {
                    error: AuthError::TokenInvalid,
                })?;

            if access_token.expires_at < chrono::Utc::now() {
                return Err(AuthenticationError {
                    error: AuthError::TokenExpired,
                });
            }

            let user = user_repo
                .find_user_by_id(access_token.user_id)
                .await
                .map_err(|e| AuthenticationError { error: e })?
                .ok_or(AuthenticationError {
                    error: AuthError::UserNotFound,
                })?;

            Ok(AuthenticatedUser {
                user,
                _marker: std::marker::PhantomData,
            })
        })
    }
}
