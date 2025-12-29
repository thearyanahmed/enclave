use std::marker::PhantomData;

use axum::extract::FromRequestParts;
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;

use super::error::AppError;
use super::routes::AppState;
use crate::{AuthError, AuthUser, TokenRepository, UserRepository};

/// validates bearer token from `Authorization` header and retrieves user
#[derive(Debug, Clone)]
pub struct AuthenticatedUser<U, T>
where
    U: UserRepository,
    T: TokenRepository,
{
    user: AuthUser,
    _marker: PhantomData<(U, T)>,
}

impl<U, T> AuthenticatedUser<U, T>
where
    U: UserRepository,
    T: TokenRepository,
{
    pub fn into_inner(self) -> AuthUser {
        self.user
    }

    pub fn user(&self) -> &AuthUser {
        &self.user
    }
}

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
