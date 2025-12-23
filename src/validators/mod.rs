pub mod email;
pub mod name;
pub mod password;

pub use email::validate_email;
pub use name::validate_name;
pub use password::{PasswordPolicy, validate_password};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationError {
    EmailEmpty,
    EmailTooLong,
    EmailInvalidFormat,
    PasswordEmpty,
    PasswordTooShort(usize),
    PasswordTooLong(usize),
    PasswordMissingUppercase,
    PasswordMissingLowercase,
    PasswordMissingDigit,
    PasswordMissingSpecial,
    PasswordCommon,
    PasswordCustom(String),
    NameEmpty,
    NameTooLong,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmailEmpty => write!(f, "Email cannot be empty"),
            Self::EmailTooLong => write!(f, "Email is too long (max 254 characters)"),
            Self::EmailInvalidFormat => write!(f, "Invalid email format"),
            Self::PasswordEmpty => write!(f, "Password cannot be empty"),
            Self::PasswordTooShort(min) => {
                write!(f, "Password must be at least {min} characters")
            }
            Self::PasswordTooLong(max) => {
                write!(f, "Password is too long (max {max} characters)")
            }
            Self::PasswordMissingUppercase => {
                write!(f, "Password must contain at least one uppercase letter")
            }
            Self::PasswordMissingLowercase => {
                write!(f, "Password must contain at least one lowercase letter")
            }
            Self::PasswordMissingDigit => {
                write!(f, "Password must contain at least one digit")
            }
            Self::PasswordMissingSpecial => {
                write!(f, "Password must contain at least one special character")
            }
            Self::PasswordCommon => write!(f, "This password is too common"),
            Self::PasswordCustom(msg) => write!(f, "{msg}"),
            Self::NameEmpty => write!(f, "Name cannot be empty"),
            Self::NameTooLong => write!(f, "Name is too long (max 100 characters)"),
        }
    }
}

impl std::error::Error for ValidationError {}
