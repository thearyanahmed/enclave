//! Authentication middleware for teams routes.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use std::marker::PhantomData;

use super::routes::TeamsState;
use crate::api::axum::error::AppError;
use crate::api::axum::middleware::extract_bearer_token;
use crate::{AuthError, AuthUser, TokenRepository, UserRepository};

/// Authenticated user extractor for teams routes.
///
/// This is similar to [`crate::api::axum::AuthenticatedUser`] but works with
/// [`TeamsState`] instead of `AppState`.
#[derive(Debug, Clone)]
pub struct TeamsAuthenticatedUser<U, T>
where
    U: UserRepository,
    T: TokenRepository,
{
    user: AuthUser,
    _marker: PhantomData<(U, T)>,
}

impl<U, T> TeamsAuthenticatedUser<U, T>
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

impl<U, T, TM, MM, IM, CM> FromRequestParts<TeamsState<U, T, TM, MM, IM, CM>>
    for TeamsAuthenticatedUser<U, T>
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    TM: Clone + Send + Sync + 'static,
    MM: Clone + Send + Sync + 'static,
    IM: Clone + Send + Sync + 'static,
    CM: Clone + Send + Sync + 'static,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &TeamsState<U, T, TM, MM, IM, CM>,
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

        Ok(TeamsAuthenticatedUser {
            user,
            _marker: PhantomData,
        })
    }
}
