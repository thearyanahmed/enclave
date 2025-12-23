use regex::Regex;
use serde::{Deserialize, Serialize};

use super::ValidationError;

/// Configuration for password validation rules.
///
/// # Examples
///
/// ```
/// use enclave::validators::PasswordPolicy;
///
/// // Default policy: 8-128 characters, no special requirements
/// let policy = PasswordPolicy::default();
/// assert!(policy.validate("password123").is_ok());
///
/// // Strict policy: 12+ chars, uppercase, lowercase, digit, special char
/// let strict = PasswordPolicy::strict();
/// assert!(strict.validate("MyP@ssw0rd123").is_ok());
/// assert!(strict.validate("weak").is_err());
/// ```
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    /// Minimum password length (default: 8)
    pub min_length: usize,
    /// Maximum password length (default: 128)
    pub max_length: usize,
    /// Require at least one uppercase letter
    pub require_uppercase: bool,
    /// Require at least one lowercase letter
    pub require_lowercase: bool,
    /// Require at least one digit
    pub require_digit: bool,
    /// Require at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?/`~'"\\)
    pub require_special: bool,
    /// Regex pattern the password must match
    #[serde(skip)]
    regex: Option<Regex>,
    /// Error message to show when regex fails
    pub regex_message: Option<String>,
    /// List of disallowed common passwords
    #[serde(default)]
    pub disallowed_passwords: Vec<String>,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 8,
            max_length: 128,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            regex: None,
            regex_message: None,
            disallowed_passwords: Vec::new(),
        }
    }
}

impl PasswordPolicy {
    /// Creates a new password policy with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a strict password policy suitable for production.
    ///
    /// Requirements:
    /// - Minimum 12 characters
    /// - At least one uppercase letter
    /// - At least one lowercase letter
    /// - At least one digit
    /// - At least one special character
    #[must_use]
    pub fn strict() -> Self {
        Self {
            min_length: 12,
            max_length: 128,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            regex: None,
            regex_message: None,
            disallowed_passwords: Vec::new(),
        }
    }

    /// Sets the minimum password length.
    #[must_use]
    pub fn min(mut self, len: usize) -> Self {
        self.min_length = len;
        self
    }

    /// Sets the maximum password length.
    #[must_use]
    pub fn max(mut self, len: usize) -> Self {
        self.max_length = len;
        self
    }

    /// Requires at least one uppercase letter.
    #[must_use]
    pub fn require_uppercase(mut self) -> Self {
        self.require_uppercase = true;
        self
    }

    /// Requires at least one lowercase letter.
    #[must_use]
    pub fn require_lowercase(mut self) -> Self {
        self.require_lowercase = true;
        self
    }

    /// Requires at least one digit.
    #[must_use]
    pub fn require_digit(mut self) -> Self {
        self.require_digit = true;
        self
    }

    /// Requires at least one special character.
    #[must_use]
    pub fn require_special(mut self) -> Self {
        self.require_special = true;
        self
    }

    /// Sets a regex pattern that passwords must match.
    #[must_use]
    pub fn regex(mut self, regex: Regex, message: impl Into<String>) -> Self {
        self.regex = Some(regex);
        self.regex_message = Some(message.into());
        self
    }

    /// Sets a list of disallowed common passwords.
    #[must_use]
    pub fn disallowed_passwords(mut self, passwords: Vec<String>) -> Self {
        self.disallowed_passwords = passwords;
        self
    }

    /// Validates a password against this policy.
    ///
    /// # Errors
    ///
    /// Returns a `ValidationError` if the password doesn't meet the policy requirements.
    pub fn validate(&self, password: &str) -> Result<(), ValidationError> {
        // Empty check
        if password.is_empty() {
            return Err(ValidationError::PasswordEmpty);
        }

        // Length checks
        if password.len() < self.min_length {
            return Err(ValidationError::PasswordTooShort(self.min_length));
        }

        if password.len() > self.max_length {
            return Err(ValidationError::PasswordTooLong(self.max_length));
        }

        // Character requirements
        if self.require_uppercase && !password.chars().any(char::is_uppercase) {
            return Err(ValidationError::PasswordMissingUppercase);
        }

        if self.require_lowercase && !password.chars().any(char::is_lowercase) {
            return Err(ValidationError::PasswordMissingLowercase);
        }

        if self.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
            return Err(ValidationError::PasswordMissingDigit);
        }

        if self.require_special && !password.chars().any(is_special_char) {
            return Err(ValidationError::PasswordMissingSpecial);
        }

        // Regex validation
        if let Some(ref regex) = self.regex {
            if !regex.is_match(password) {
                let msg = self
                    .regex_message
                    .clone()
                    .unwrap_or_else(|| "Password does not meet requirements".to_owned());
                return Err(ValidationError::PasswordCustom(msg));
            }
        }

        // Blocklist check (case-insensitive)
        if self
            .disallowed_passwords
            .iter()
            .any(|p| p.eq_ignore_ascii_case(password))
        {
            return Err(ValidationError::PasswordCommon);
        }

        Ok(())
    }
}

/// Checks if a character is a special character.
fn is_special_char(c: char) -> bool {
    matches!(
        c,
        '!' | '@'
            | '#'
            | '$'
            | '%'
            | '^'
            | '&'
            | '*'
            | '('
            | ')'
            | '_'
            | '+'
            | '-'
            | '='
            | '['
            | ']'
            | '{'
            | '}'
            | '|'
            | ';'
            | ':'
            | ','
            | '.'
            | '<'
            | '>'
            | '?'
            | '/'
            | '`'
            | '~'
            | '\''
            | '"'
            | '\\'
    )
}

/// Validates a password using the default policy (8-128 characters).
///
/// For custom validation rules, use [`PasswordPolicy`] directly.
pub fn validate_password(password: &str) -> Result<(), ValidationError> {
    PasswordPolicy::default().validate(password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy_valid_passwords() {
        let policy = PasswordPolicy::default();
        assert!(policy.validate("password123").is_ok());
        assert!(policy.validate("12345678").is_ok());
        assert!(policy.validate("a]b@c#d$e%f^g&h*").is_ok());
    }

    #[test]
    fn test_password_empty() {
        let policy = PasswordPolicy::default();
        assert_eq!(
            policy.validate("").unwrap_err(),
            ValidationError::PasswordEmpty
        );
    }

    #[test]
    fn test_password_too_short() {
        let policy = PasswordPolicy::default();
        assert_eq!(
            policy.validate("1234567").unwrap_err(),
            ValidationError::PasswordTooShort(8)
        );
        assert_eq!(
            policy.validate("abc").unwrap_err(),
            ValidationError::PasswordTooShort(8)
        );
    }

    #[test]
    fn test_password_too_long() {
        let policy = PasswordPolicy::default();
        let long_password = "a".repeat(129);
        assert_eq!(
            policy.validate(&long_password).unwrap_err(),
            ValidationError::PasswordTooLong(128)
        );
    }

    #[test]
    fn test_strict_policy() {
        let policy = PasswordPolicy::strict();

        // Valid strict password
        assert!(policy.validate("MyP@ssw0rd123").is_ok());

        // Missing uppercase
        assert_eq!(
            policy.validate("myp@ssw0rd123").unwrap_err(),
            ValidationError::PasswordMissingUppercase
        );

        // Missing lowercase
        assert_eq!(
            policy.validate("MYP@SSW0RD123").unwrap_err(),
            ValidationError::PasswordMissingLowercase
        );

        // Missing digit
        assert_eq!(
            policy.validate("MyP@sswordabc").unwrap_err(),
            ValidationError::PasswordMissingDigit
        );

        // Missing special
        assert_eq!(
            policy.validate("MyPassword1234").unwrap_err(),
            ValidationError::PasswordMissingSpecial
        );

        // Too short
        assert_eq!(
            policy.validate("MyP@ss0").unwrap_err(),
            ValidationError::PasswordTooShort(12)
        );
    }

    #[test]
    fn test_custom_min_length() {
        let policy = PasswordPolicy::new().min(10);
        assert!(policy.validate("1234567890").is_ok());
        assert_eq!(
            policy.validate("123456789").unwrap_err(),
            ValidationError::PasswordTooShort(10)
        );
    }

    #[test]
    fn test_builder_pattern() {
        let policy = PasswordPolicy::new()
            .min(10)
            .require_uppercase()
            .require_digit();

        assert!(policy.validate("Password12").is_ok());
        assert_eq!(
            policy.validate("password12").unwrap_err(),
            ValidationError::PasswordMissingUppercase
        );
        assert_eq!(
            policy.validate("Passwordab").unwrap_err(),
            ValidationError::PasswordMissingDigit
        );
    }

    #[test]
    fn test_regex() {
        let regex = Regex::new(r"^[a-zA-Z0-9]+$").unwrap();
        let policy = PasswordPolicy::new().regex(regex, "Password must be alphanumeric only");

        assert!(policy.validate("Password123").is_ok());
        assert_eq!(
            policy.validate("Password@123").unwrap_err(),
            ValidationError::PasswordCustom("Password must be alphanumeric only".to_owned())
        );
    }

    #[test]
    fn test_disallowed_passwords() {
        let policy = PasswordPolicy::new().disallowed_passwords(vec![
            "password".to_owned(),
            "12345678".to_owned(),
            "qwerty123".to_owned(),
        ]);

        assert!(policy.validate("mypassword1").is_ok());
        assert_eq!(
            policy.validate("password").unwrap_err(),
            ValidationError::PasswordCommon
        );
        assert_eq!(
            policy.validate("PASSWORD").unwrap_err(), // case-insensitive
            ValidationError::PasswordCommon
        );
        assert_eq!(
            policy.validate("12345678").unwrap_err(),
            ValidationError::PasswordCommon
        );
    }

    #[test]
    fn test_validate_password_function() {
        // The standalone function should use default policy
        assert!(validate_password("password123").is_ok());
        assert!(validate_password("1234567").is_err());
    }
}
