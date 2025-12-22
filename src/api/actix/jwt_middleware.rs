use actix_web::{FromRequest, HttpRequest, HttpResponse, dev::Payload, http::header, web};
use std::future::Future;
use std::pin::Pin;

use crate::jwt::JwtService;
use crate::{AuthError, User, UserRepository};

/// JWT-authenticated user extractor.
///
/// Use this in handler parameters to require JWT authentication.
/// The extractor validates the JWT token and retrieves the associated user.
///
/// # Example
/// ```ignore
/// async fn protected_handler(
///     user: JwtAuthenticatedUser<MyUserRepo>,
/// ) -> impl Responder {
///     format!("Hello, {}!", user.user().email)
/// }
/// ```
#[derive(Debug, Clone)]
pub struct JwtAuthenticatedUser<U>
where
    U: UserRepository,
{
    user: User,
    _marker: std::marker::PhantomData<U>,
}

impl<U> JwtAuthenticatedUser<U>
where
    U: UserRepository,
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

/// Error type for JWT authentication failures.
#[derive(Debug)]
pub struct JwtAuthenticationError {
    pub error: AuthError,
}

impl std::fmt::Display for JwtAuthenticationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl actix_web::ResponseError for JwtAuthenticationError {
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
fn extract_bearer_token(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()
        .and_then(|auth| auth.strip_prefix("Bearer "))
        .map(ToOwned::to_owned)
}

impl<U> FromRequest for JwtAuthenticatedUser<U>
where
    U: UserRepository + Clone + Send + Sync + 'static,
{
    type Error = JwtAuthenticationError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let token = extract_bearer_token(req);

        let jwt_service = req
            .app_data::<web::Data<JwtService>>()
            .map(|data| data.get_ref().clone());

        let user_repo = req
            .app_data::<web::Data<U>>()
            .map(|data| data.get_ref().clone());

        Box::pin(async move {
            let token = token.ok_or(JwtAuthenticationError {
                error: AuthError::TokenInvalid,
            })?;

            let jwt_service = jwt_service.ok_or(JwtAuthenticationError {
                error: AuthError::TokenInvalid,
            })?;

            let user_repo = user_repo.ok_or(JwtAuthenticationError {
                error: AuthError::TokenInvalid,
            })?;

            // Validate JWT and extract user_id
            let user_id = jwt_service
                .validate(&token)
                .map_err(|e| JwtAuthenticationError { error: e })?;

            let user = user_repo
                .find_user_by_id(user_id)
                .await
                .map_err(|e| JwtAuthenticationError { error: e })?
                .ok_or(JwtAuthenticationError {
                    error: AuthError::UserNotFound,
                })?;

            Ok(JwtAuthenticatedUser {
                user,
                _marker: std::marker::PhantomData,
            })
        })
    }
}
