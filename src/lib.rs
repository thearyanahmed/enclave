pub mod actions;
pub mod repository;

pub use repository::UserRepository;
pub use repository::User;

pub use repository::MockUserRepository;
use std::fmt;

#[derive(Debug, Clone)]
pub enum AuthError {
    Other(String),
}

impl std::error::Error for AuthError {}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

