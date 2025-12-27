//! Error handling for Axum API layer.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::AuthError;
use crate::api::ErrorResponse;

/// Application error wrapper for Axum responses.
///
/// Converts [`AuthError`] into appropriate HTTP responses with JSON error bodies.
#[derive(Debug)]
pub struct AppError(pub AuthError);

impl From<AuthError> for AppError {
    fn from(err: AuthError) -> Self {
        Self(err)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let error_response = ErrorResponse::from(self.0.clone());
        let status = match &self.0 {
            AuthError::TooManyAttempts => StatusCode::TOO_MANY_REQUESTS,
            AuthError::InvalidEmail
            | AuthError::InvalidPassword
            | AuthError::Validation(_)
            | AuthError::UserAlreadyExists
            | AuthError::TokenInvalid
            | AuthError::EmailAlreadyVerified => StatusCode::BAD_REQUEST,
            AuthError::InvalidCredentials | AuthError::UserNotFound | AuthError::TokenExpired => {
                StatusCode::UNAUTHORIZED
            }
            AuthError::NotFound => StatusCode::NOT_FOUND,
            #[allow(deprecated)]
            AuthError::DatabaseError(_)
            | AuthError::ConfigurationError(_)
            | AuthError::PasswordHashError
            | AuthError::Internal(_)
            | AuthError::Other(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (status, Json(error_response)).into_response()
    }
}
