use actix_web::cookie::time::Duration as CookieDuration;
use actix_web::cookie::{Cookie, SameSite as ActixSameSite};
use actix_web::{HttpRequest, HttpResponse, web};
use chrono::Utc;

use super::session_middleware::SessionAuthenticatedUser;
use crate::actions::LoginAction;
use crate::api::{ErrorResponse, LoginRequest, MessageResponse};
use crate::crypto::Argon2Hasher;
use crate::session::{SameSite, SessionConfig, SessionData, SessionRepository, sign_session_id};
use crate::{AuthError, RateLimiterRepository, SecretString, UserRepository};

#[derive(Debug, serde::Serialize)]
pub struct SessionUserResponse {
    pub user_id: i64,
    pub email: String,
    pub name: String,
}

fn build_session_cookie(signed_value: String, config: &SessionConfig) -> Cookie<'static> {
    let same_site = match config.cookie_same_site {
        SameSite::None => ActixSameSite::None,
        SameSite::Lax => ActixSameSite::Lax,
        SameSite::Strict => ActixSameSite::Strict,
    };

    let max_age_secs = config.session_lifetime.num_seconds();

    let mut cookie = Cookie::build(config.cookie_name.clone(), signed_value)
        .path(config.cookie_path.clone())
        .secure(config.cookie_secure)
        .http_only(config.cookie_http_only)
        .same_site(same_site)
        .max_age(CookieDuration::seconds(max_age_secs))
        .finish();

    if let Some(ref domain) = config.cookie_domain {
        cookie.set_domain(domain.clone());
    }

    cookie
}

fn build_removal_cookie(config: &SessionConfig) -> Cookie<'static> {
    Cookie::build(config.cookie_name.clone(), String::new())
        .path(config.cookie_path.clone())
        .max_age(CookieDuration::ZERO)
        .finish()
}

fn extract_session_id(req: &HttpRequest, config: &SessionConfig) -> Option<String> {
    req.cookie(&config.cookie_name)
        .and_then(|c| crate::session::verify_signed_cookie(c.value(), &config.secret_key))
}

pub async fn session_login<U, S, R>(
    body: web::Json<LoginRequest>,
    user_repo: web::Data<U>,
    session_repo: web::Data<S>,
    rate_limiter: web::Data<R>,
    session_config: web::Data<SessionConfig>,
) -> HttpResponse
where
    U: UserRepository + Clone + 'static,
    S: SessionRepository + Clone + 'static,
    R: RateLimiterRepository + Clone + 'static,
{
    // Use a mock token repo for login action - we don't create tokens for sessions
    let action = LoginAction::<U, MockTokenRepo, R, Argon2Hasher>::new(
        user_repo.get_ref().clone(),
        MockTokenRepo,
        rate_limiter.get_ref().clone(),
    );
    let password = SecretString::new(&body.password);

    match action.execute(&body.email, &password).await {
        Ok((user, _token)) => {
            let session_data = SessionData {
                user_id: user.id,
                email: user.email.clone(),
                name: user.name.clone(),
                created_at: Utc::now(),
                expires_at: Utc::now() + session_config.session_lifetime,
            };

            match session_repo.create(session_data).await {
                Ok(session_id) => {
                    let signed_value = sign_session_id(&session_id, &session_config.secret_key);
                    let cookie = build_session_cookie(signed_value, &session_config);

                    HttpResponse::Ok().cookie(cookie).json(SessionUserResponse {
                        user_id: user.id,
                        email: user.email,
                        name: user.name,
                    })
                }
                Err(err) => {
                    let error_response = ErrorResponse::from(err);
                    HttpResponse::InternalServerError().json(error_response)
                }
            }
        }
        Err(err) => {
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

pub async fn session_logout<S>(
    req: HttpRequest,
    session_repo: web::Data<S>,
    session_config: web::Data<SessionConfig>,
) -> HttpResponse
where
    S: SessionRepository + Clone + 'static,
{
    if let Some(session_id) = extract_session_id(&req, &session_config) {
        let _ = session_repo.destroy(&session_id).await;
    }

    HttpResponse::Ok()
        .cookie(build_removal_cookie(&session_config))
        .json(MessageResponse {
            message: "Successfully logged out".to_owned(),
        })
}

pub async fn session_get_user<S>(session: SessionAuthenticatedUser<S>) -> HttpResponse
where
    S: SessionRepository + Clone + 'static,
{
    HttpResponse::Ok().json(SessionUserResponse {
        user_id: session.user_id(),
        email: session.email().to_owned(),
        name: session.name().to_owned(),
    })
}

/// `LoginAction` requires a `TokenRepository`, but for sessions we create sessions instead
#[derive(Clone)]
struct MockTokenRepo;

#[async_trait::async_trait]
impl crate::TokenRepository for MockTokenRepo {
    async fn create_token(
        &self,
        user_id: i64,
        expires_at: chrono::DateTime<Utc>,
    ) -> Result<crate::AccessToken, AuthError> {
        // Return a dummy token - it won't be used
        Ok(crate::AccessToken {
            user_id,
            token: SecretString::new("unused"),
            name: None,
            expires_at,
            created_at: Utc::now(),
        })
    }

    async fn create_token_with_options(
        &self,
        user_id: i64,
        expires_at: chrono::DateTime<Utc>,
        options: crate::repository::CreateTokenOptions,
    ) -> Result<crate::AccessToken, AuthError> {
        Ok(crate::AccessToken {
            user_id,
            token: SecretString::new("unused"),
            name: options.name,
            expires_at,
            created_at: Utc::now(),
        })
    }

    async fn find_token(&self, _token: &str) -> Result<Option<crate::AccessToken>, AuthError> {
        Ok(None)
    }
}
