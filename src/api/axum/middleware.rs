//! Authentication middleware for Axum handlers.

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::HeaderMap;
use std::marker::PhantomData;

use super::error::AppError;
use super::routes::AppState;
use crate::{AuthError, TokenRepository, User, UserRepository};

/// Authenticated user extractor for Axum handlers.
///
/// Use this in handler parameters to require authentication.
/// The extractor validates the bearer token from the `Authorization` header
/// and retrieves the associated user from the repository.
///
/// # Example
///
/// ```rust,ignore
/// use enclave::api::axum::AuthenticatedUser;
///
/// async fn protected_handler<U, T>(
///     user: AuthenticatedUser<U, T>,
/// ) -> impl IntoResponse
/// where
///     U: UserRepository + Clone + Send + Sync + 'static,
///     T: TokenRepository + Clone + Send + Sync + 'static,
/// {
///     Json(UserResponse::from(user.into_inner()))
/// }
/// ```
#[derive(Debug, Clone)]
pub struct AuthenticatedUser<U, T>
where
    U: UserRepository,
    T: TokenRepository,
{
    user: User,
    _marker: PhantomData<(U, T)>,
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

/// Extracts the bearer token from the Authorization header.
pub fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(AUTHORIZATION)?
        .to_str()
        .ok()
        .and_then(|auth| auth.strip_prefix("Bearer "))
        .map(ToOwned::to_owned)
}

impl<U, T, R, P, E> FromRequestParts<AppState<U, T, R, P, E>> for AuthenticatedUser<U, T>
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    P: Clone + Send + Sync + 'static,
    E: Clone + Send + Sync + 'static,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState<U, T, R, P, E>,
    ) -> Result<Self, Self::Rejection> {
        let token =
            extract_bearer_token(&parts.headers).ok_or(AppError(AuthError::TokenInvalid))?;

        let token_repo = &state.token_repo;
        let user_repo = &state.user_repo;

        // find_token handles hashing internally
        let access_token = token_repo
            .find_token(&token)
            .await
            .map_err(AppError)?
            .ok_or(AppError(AuthError::TokenInvalid))?;

        if access_token.expires_at < chrono::Utc::now() {
            return Err(AppError(AuthError::TokenExpired));
        }

        let user = user_repo
            .find_user_by_id(access_token.user_id)
            .await
            .map_err(AppError)?
            .ok_or(AppError(AuthError::UserNotFound))?;

        Ok(AuthenticatedUser {
            user,
            _marker: PhantomData,
        })
    }
}
