pub mod email;
pub mod password;
pub mod name;

pub use email::validate_email;
pub use password::validate_password;
pub use name::validate_name;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationError {
    EmailEmpty,
    EmailTooLong,
    EmailInvalidFormat,
    PasswordEmpty,
    PasswordTooShort,
    PasswordTooLong,
    NameEmpty,
    NameTooLong,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::EmailEmpty => write!(f, "Email cannot be empty"),
            ValidationError::EmailTooLong => write!(f, "Email is too long (max 254 characters)"),
            ValidationError::EmailInvalidFormat => write!(f, "Invalid email format"),
            ValidationError::PasswordEmpty => write!(f, "Password cannot be empty"),
            ValidationError::PasswordTooShort => write!(f, "Password must be at least 8 characters"),
            ValidationError::PasswordTooLong => write!(f, "Password is too long (max 128 characters)"),
            ValidationError::NameEmpty => write!(f, "Name cannot be empty"),
            ValidationError::NameTooLong => write!(f, "Name is too long (max 100 characters)"),
        }
    }
}

impl std::error::Error for ValidationError {}
