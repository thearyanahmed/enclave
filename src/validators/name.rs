use super::ValidationError;

pub fn validate_name(name: &str) -> Result<(), ValidationError> {
    let trimmed = name.trim();

    if trimmed.is_empty() {
        return Err(ValidationError::NameEmpty);
    }

    if trimmed.len() > 100 {
        return Err(ValidationError::NameTooLong);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_names() {
        assert!(validate_name("John").is_ok());
        assert!(validate_name("John Doe").is_ok());
        assert!(validate_name("José García").is_ok());
        assert!(validate_name("名前").is_ok());
    }

    #[test]
    fn test_name_empty() {
        assert_eq!(validate_name("").unwrap_err(), ValidationError::NameEmpty);
        assert_eq!(validate_name("   ").unwrap_err(), ValidationError::NameEmpty);
    }

    #[test]
    fn test_name_too_long() {
        let long_name = "a".repeat(101);
        assert_eq!(validate_name(&long_name).unwrap_err(), ValidationError::NameTooLong);
    }
}
