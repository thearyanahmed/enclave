use actix_web::{FromRequest, HttpRequest, HttpResponse, dev::Payload, http::header, web};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::crypto::hash_token;
use crate::{AuthError, TokenRepository, User, UserRepository};

/// Authenticated user extractor.
///
/// Use this in handler parameters to require authentication.
/// The extractor validates the bearer token and retrieves the associated user.
///
/// # Example
/// ```ignore
/// async fn protected_handler(
///     user: AuthenticatedUser<MyUserRepo, MyTokenRepo>,
/// ) -> impl Responder {
///     format!("Hello, {}!", user.user().email)
/// }
/// ```
#[derive(Debug, Clone)]
pub struct AuthenticatedUser<U, T>
where
    U: UserRepository,
    T: TokenRepository,
{
    user: User,
    _marker: std::marker::PhantomData<(U, T)>,
}

impl<U, T> AuthenticatedUser<U, T>
where
    U: UserRepository,
    T: TokenRepository,
{
    /// Returns the inner user, consuming the wrapper.
    pub fn into_inner(self) -> User {
        self.user
    }

    /// Returns a reference to the authenticated user.
    pub fn user(&self) -> &User {
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
            .app_data::<web::Data<Arc<T>>>()
            .map(|data| Arc::clone(data.as_ref()));

        let user_repo = req
            .app_data::<web::Data<Arc<U>>>()
            .map(|data| Arc::clone(data.as_ref()));

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

            let hashed_token = hash_token(&token);

            let access_token = token_repo
                .find_token(&hashed_token)
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
