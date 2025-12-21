pub mod actions;
pub mod repository;

pub use repository::UserRepository;
pub use repository::TokenRepository;
pub use repository::User;
pub use repository::AccessToken;

pub use repository::MockUserRepository;
pub use repository::MockTokenRepository;
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum AuthError {
    UserNotFound,
    UserAlreadyExists,
    InvalidCredentials,
    InvalidEmail,
    InvalidPassword,
    PasswordHashError,
    DatabaseError(String),
    #[deprecated(note = "Use specific error variants instead")]
    Other(String),
}

impl std::error::Error for AuthError {}

impl fmt::Display for AuthError {
    #[allow(deprecated)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::UserNotFound => write!(f, "User not found"),
            AuthError::UserAlreadyExists => write!(f, "User already exists"),
            AuthError::InvalidCredentials => write!(f, "Invalid email or password"),
            AuthError::InvalidEmail => write!(f, "Invalid email format"),
            AuthError::InvalidPassword => write!(f, "Invalid password"),
            AuthError::PasswordHashError => write!(f, "Failed to hash password"),
            AuthError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            AuthError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

