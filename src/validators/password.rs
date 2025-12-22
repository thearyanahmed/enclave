use super::ValidationError;

pub fn validate_password(password: &str) -> Result<(), ValidationError> {
    if password.is_empty() {
        return Err(ValidationError::PasswordEmpty);
    }

    if password.len() < 8 {
        return Err(ValidationError::PasswordTooShort);
    }

    if password.len() > 128 {
        return Err(ValidationError::PasswordTooLong);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_passwords() {
        assert!(validate_password("password123").is_ok());
        assert!(validate_password("12345678").is_ok());
        assert!(validate_password("a]b@c#d$e%f^g&h*").is_ok());
    }

    #[test]
    fn test_password_empty() {
        assert_eq!(
            validate_password("").unwrap_err(),
            ValidationError::PasswordEmpty
        );
    }

    #[test]
    fn test_password_too_short() {
        assert_eq!(
            validate_password("1234567").unwrap_err(),
            ValidationError::PasswordTooShort
        );
        assert_eq!(
            validate_password("abc").unwrap_err(),
            ValidationError::PasswordTooShort
        );
    }

    #[test]
    fn test_password_too_long() {
        let long_password = "a".repeat(129);
        assert_eq!(
            validate_password(&long_password).unwrap_err(),
            ValidationError::PasswordTooLong
        );
    }
}
