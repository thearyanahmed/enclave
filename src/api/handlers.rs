use actix_web::{HttpRequest, HttpResponse, web};
use std::sync::Arc;

use crate::actions::{
    ChangePasswordAction, ForgotPasswordAction, LoginAction, LogoutAction, RefreshTokenAction,
    ResetPasswordAction, SignupAction, UpdateUserAction, VerifyEmailAction,
};
use crate::api::middleware::{AuthenticatedUser, extract_bearer_token};
use crate::api::{
    AuthResponse, ChangePasswordRequest, ErrorResponse, ForgotPasswordRequest, LoginRequest,
    MessageResponse, RefreshTokenRequest, RegisterRequest, ResetPasswordRequest, TokenResponse,
    UpdateUserRequest, UserResponse, VerifyEmailRequest,
};
use crate::crypto::hash_token;
use crate::{
    EmailVerificationRepository, PasswordResetRepository, RateLimiterRepository, TokenRepository,
    UserRepository,
};

pub async fn register<U>(
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

pub async fn logout<T>(req: HttpRequest, token_repo: web::Data<Arc<T>>) -> HttpResponse
where
    T: TokenRepository + Clone + Send + Sync + 'static,
{
    let token = match extract_bearer_token(&req) {
        Some(t) => t,
        None => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "Missing authorization token".to_owned(),
                code: "TOKEN_INVALID".to_owned(),
            });
        }
    };

    let action = LogoutAction::new(token_repo.as_ref().as_ref().clone());
    let hashed = hash_token(&token);

    match action.execute(&hashed).await {
        Ok(()) => HttpResponse::Ok().json(MessageResponse {
            message: "Successfully logged out".to_owned(),
        }),
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            HttpResponse::BadRequest().json(error_response)
        }
    }
}

pub async fn forgot_password<U, P>(
    body: web::Json<ForgotPasswordRequest>,
    user_repo: web::Data<Arc<U>>,
    reset_repo: web::Data<Arc<P>>,
) -> HttpResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    P: PasswordResetRepository + Clone + Send + Sync + 'static,
{
    let action = ForgotPasswordAction::new(
        user_repo.as_ref().as_ref().clone(),
        reset_repo.as_ref().as_ref().clone(),
    );

    // Don't reveal whether user exists - always return success regardless of result
    let _ = action.execute(&body.email).await;

    HttpResponse::Ok().json(MessageResponse {
        message: "If the email exists, a password reset link has been sent".to_owned(),
    })
}

pub async fn reset_password<U, P>(
    body: web::Json<ResetPasswordRequest>,
    user_repo: web::Data<Arc<U>>,
    reset_repo: web::Data<Arc<P>>,
) -> HttpResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    P: PasswordResetRepository + Clone + Send + Sync + 'static,
{
    let action = ResetPasswordAction::new(
        user_repo.as_ref().as_ref().clone(),
        reset_repo.as_ref().as_ref().clone(),
    );

    match action.execute(&body.token, &body.password).await {
        Ok(()) => HttpResponse::Ok().json(MessageResponse {
            message: "Password has been reset successfully".to_owned(),
        }),
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            HttpResponse::BadRequest().json(error_response)
        }
    }
}

pub async fn refresh_token<T>(
    body: web::Json<RefreshTokenRequest>,
    token_repo: web::Data<Arc<T>>,
) -> HttpResponse
where
    T: TokenRepository + Clone + Send + Sync + 'static,
{
    let action = RefreshTokenAction::new(token_repo.as_ref().as_ref().clone());
    let hashed = hash_token(&body.token);

    match action.execute(&hashed).await {
        Ok(new_token) => HttpResponse::Ok().json(TokenResponse {
            token: new_token.token,
            expires_at: new_token.expires_at,
        }),
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            HttpResponse::Unauthorized().json(error_response)
        }
    }
}

pub async fn verify_email<U, E>(
    body: web::Json<VerifyEmailRequest>,
    user_repo: web::Data<Arc<U>>,
    verification_repo: web::Data<Arc<E>>,
) -> HttpResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    E: EmailVerificationRepository + Clone + Send + Sync + 'static,
{
    let action = VerifyEmailAction::new(
        user_repo.as_ref().as_ref().clone(),
        verification_repo.as_ref().as_ref().clone(),
    );

    match action.execute(&body.token).await {
        Ok(()) => HttpResponse::Ok().json(MessageResponse {
            message: "Email verified successfully".to_owned(),
        }),
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            HttpResponse::BadRequest().json(error_response)
        }
    }
}

pub async fn get_current_user<U, T>(user: AuthenticatedUser<U, T>) -> HttpResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
{
    HttpResponse::Ok().json(UserResponse::from(user.into_inner()))
}

pub async fn update_user<U, T>(
    user: AuthenticatedUser<U, T>,
    body: web::Json<UpdateUserRequest>,
    user_repo: web::Data<Arc<U>>,
) -> HttpResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
{
    let action = UpdateUserAction::new(user_repo.as_ref().as_ref().clone());

    match action
        .execute(user.user().id, &body.name, &body.email)
        .await
    {
        Ok(updated_user) => HttpResponse::Ok().json(UserResponse::from(updated_user)),
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            HttpResponse::BadRequest().json(error_response)
        }
    }
}

pub async fn change_password<U, T>(
    user: AuthenticatedUser<U, T>,
    body: web::Json<ChangePasswordRequest>,
    user_repo: web::Data<Arc<U>>,
) -> HttpResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
{
    let action = ChangePasswordAction::new(user_repo.as_ref().as_ref().clone());

    match action
        .execute(user.user().id, &body.current_password, &body.new_password)
        .await
    {
        Ok(()) => HttpResponse::Ok().json(MessageResponse {
            message: "Password changed successfully".to_owned(),
        }),
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            HttpResponse::BadRequest().json(error_response)
        }
    }
}
