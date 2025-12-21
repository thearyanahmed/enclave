use regex::Regex;
use std::sync::LazyLock;

static EMAIL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap()
});

pub fn validate_email(email: &str) -> Result<(), ValidationError> {
    if email.is_empty() {
        return Err(ValidationError::EmailEmpty);
    }

    if email.len() > 254 {
        return Err(ValidationError::EmailTooLong);
    }

    if !EMAIL_REGEX.is_match(email) {
        return Err(ValidationError::EmailInvalidFormat);
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq)]
pub enum ValidationError {
    EmailEmpty,
    EmailTooLong,
    EmailInvalidFormat,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::EmailEmpty => write!(f, "Email cannot be empty"),
            ValidationError::EmailTooLong => write!(f, "Email is too long (max 254 characters)"),
            ValidationError::EmailInvalidFormat => write!(f, "Invalid email format"),
        }
    }
}

impl std::error::Error for ValidationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_emails() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("user.name@example.com").is_ok());
        assert!(validate_email("user+tag@example.com").is_ok());
        assert!(validate_email("user@subdomain.example.com").is_ok());
    }

    #[test]
    fn test_invalid_emails() {
        assert_eq!(validate_email("").unwrap_err(), ValidationError::EmailEmpty);
        assert_eq!(validate_email("notanemail").unwrap_err(), ValidationError::EmailInvalidFormat);
        assert_eq!(validate_email("missing@domain").unwrap_err(), ValidationError::EmailInvalidFormat);
        assert_eq!(validate_email("@nodomain.com").unwrap_err(), ValidationError::EmailInvalidFormat);
        assert_eq!(validate_email("spaces in@email.com").unwrap_err(), ValidationError::EmailInvalidFormat);
    }

    #[test]
    fn test_email_too_long() {
        let long_email = format!("{}@example.com", "a".repeat(250));
        assert_eq!(validate_email(&long_email).unwrap_err(), ValidationError::EmailTooLong);
    }
}
