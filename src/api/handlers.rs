use actix_web::{web, HttpResponse};
use std::sync::Arc;

use crate::api::{AuthResponse, ErrorResponse, LoginRequest, RegisterRequest, UserResponse};
use crate::actions::{LoginAction, SignupAction};
use crate::{RateLimiterRepository, TokenRepository, UserRepository};

pub async fn register<U, T, R>(
    body: web::Json<RegisterRequest>,
    user_repo: web::Data<Arc<U>>,
) -> HttpResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
{
    let action = SignupAction::new(user_repo.as_ref().as_ref().clone());

    match action.execute(&body.email, &body.password).await {
        Ok(user) => HttpResponse::Created().json(UserResponse::from(user)),
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            HttpResponse::BadRequest().json(error_response)
        }
    }
}

pub async fn login<U, T, R>(
    body: web::Json<LoginRequest>,
    user_repo: web::Data<Arc<U>>,
    token_repo: web::Data<Arc<T>>,
    rate_limiter: web::Data<Arc<R>>,
) -> HttpResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    R: RateLimiterRepository + Clone + Send + Sync + 'static,
{
    let action = LoginAction::new(
        user_repo.as_ref().as_ref().clone(),
        token_repo.as_ref().as_ref().clone(),
        rate_limiter.as_ref().as_ref().clone(),
    );

    match action.execute(&body.email, &body.password).await {
        Ok((user, token)) => HttpResponse::Ok().json(AuthResponse {
            user: UserResponse::from(user),
            token: token.token,
            expires_at: token.expires_at,
        }),
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            HttpResponse::Unauthorized().json(error_response)
        }
    }
}
