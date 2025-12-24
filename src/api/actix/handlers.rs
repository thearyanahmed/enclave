use actix_web::{HttpRequest, HttpResponse, web};

use super::middleware::{AuthenticatedUser, extract_bearer_token};
use crate::actions::{
    ChangePasswordAction, ForgotPasswordAction, LoginAction, LogoutAction, RefreshTokenAction,
    ResetPasswordAction, SignupAction, UpdateUserAction, VerifyEmailAction,
};
use crate::api::{
    AuthResponse, ChangePasswordRequest, ErrorResponse, ForgotPasswordRequest, LoginRequest,
    MessageResponse, RefreshTokenRequest, RegisterRequest, ResetPasswordRequest, TokenResponse,
    UpdateUserRequest, UserResponse, VerifyEmailRequest,
};
use crate::crypto::SecretString;
use crate::{
    AuthError, EmailVerificationRepository, PasswordResetRepository, RateLimiterRepository,
    TokenRepository, UserRepository,
};

pub async fn register<U>(body: web::Json<RegisterRequest>, user_repo: web::Data<U>) -> HttpResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
{
    let action = SignupAction::new(user_repo.get_ref().clone());
    let password = SecretString::new(&body.password);

    match action.execute(&body.email, &password).await {
        Ok(user) => HttpResponse::Created().json(UserResponse::from(user)),
        Err(err) => {
            let error_response = ErrorResponse::from(err);
            HttpResponse::BadRequest().json(error_response)
        }
    }
}

pub async fn login<U, T, R>(
    body: web::Json<LoginRequest>,
    user_repo: web::Data<U>,
    token_repo: web::Data<T>,
    rate_limiter: web::Data<R>,
) -> HttpResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
    R: RateLimiterRepository + Clone + Send + Sync + 'static,
{
    let action = LoginAction::new(
        user_repo.get_ref().clone(),
        token_repo.get_ref().clone(),
        rate_limiter.get_ref().clone(),
    );
    let password = SecretString::new(&body.password);

    match action.execute(&body.email, &password).await {
        Ok((user, token)) => HttpResponse::Ok().json(AuthResponse {
            user: UserResponse::from(user),
            token: token.token,
            expires_at: token.expires_at,
        }),
        Err(err) => {
            // Clone required: err is consumed by ErrorResponse::from() but also needed for match
            let error_response = ErrorResponse::from(err.clone());
            match err {
                AuthError::TooManyAttempts => HttpResponse::TooManyRequests().json(error_response),
                AuthError::InvalidEmail | AuthError::InvalidPassword | AuthError::Validation(_) => {
                    HttpResponse::BadRequest().json(error_response)
                }
                AuthError::InvalidCredentials | AuthError::UserNotFound => {
                    HttpResponse::Unauthorized().json(error_response)
                }
                _ => HttpResponse::InternalServerError().json(error_response),
            }
        }
    }
}

pub async fn logout<T>(req: HttpRequest, token_repo: web::Data<T>) -> HttpResponse
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

    let action = LogoutAction::new(token_repo.get_ref().clone());

    // revoke_token handles hashing internally
    match action.execute(&token).await {
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
    user_repo: web::Data<U>,
    reset_repo: web::Data<P>,
) -> HttpResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    P: PasswordResetRepository + Clone + Send + Sync + 'static,
{
    let action =
        ForgotPasswordAction::new(user_repo.get_ref().clone(), reset_repo.get_ref().clone());

    // Don't reveal whether user exists - always return success regardless of result
    let _ = action.execute(&body.email).await;

    HttpResponse::Ok().json(MessageResponse {
        message: "If the email exists, a password reset link has been sent".to_owned(),
    })
}

pub async fn reset_password<U, P>(
    body: web::Json<ResetPasswordRequest>,
    user_repo: web::Data<U>,
    reset_repo: web::Data<P>,
) -> HttpResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    P: PasswordResetRepository + Clone + Send + Sync + 'static,
{
    let action =
        ResetPasswordAction::new(user_repo.get_ref().clone(), reset_repo.get_ref().clone());
    let password = SecretString::new(&body.password);

    match action.execute(&body.token, &password).await {
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
    token_repo: web::Data<T>,
) -> HttpResponse
where
    T: TokenRepository + Clone + Send + Sync + 'static,
{
    let action = RefreshTokenAction::new(token_repo.get_ref().clone());

    // refresh internally handles token hashing
    match action.execute(&body.token).await {
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
    user_repo: web::Data<U>,
    verification_repo: web::Data<E>,
) -> HttpResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    E: EmailVerificationRepository + Clone + Send + Sync + 'static,
{
    let action = VerifyEmailAction::new(
        user_repo.get_ref().clone(),
        verification_repo.get_ref().clone(),
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
    user_repo: web::Data<U>,
) -> HttpResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
{
    let action = UpdateUserAction::new(user_repo.get_ref().clone());

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
    user_repo: web::Data<U>,
) -> HttpResponse
where
    U: UserRepository + Clone + Send + Sync + 'static,
    T: TokenRepository + Clone + Send + Sync + 'static,
{
    let action = ChangePasswordAction::new(user_repo.get_ref().clone());
    let current_password = SecretString::new(&body.current_password);
    let new_password = SecretString::new(&body.new_password);

    match action
        .execute(user.user().id, &current_password, &new_password)
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
