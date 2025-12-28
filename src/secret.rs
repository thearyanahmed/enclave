//! Sensitive data wrapper types.
//!
//! This module provides types for handling sensitive data that should not be
//! accidentally logged or printed.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A wrapper for sensitive string data that prevents accidental logging.
///
/// `SecretString` implements `Debug` and `Display` to show `[REDACTED]` instead
/// of the actual content, preventing sensitive data from being accidentally
/// logged or printed.
///
/// # Example
///
/// ```rust
/// use enclave::SecretString;
///
/// let password = SecretString::new("my_secret_password");
///
/// // Debug output shows [REDACTED]
/// assert_eq!(format!("{:?}", password), "SecretString([REDACTED])");
///
/// // Access the actual value when needed
/// assert_eq!(password.expose_secret(), "my_secret_password");
/// ```
#[derive(Clone)]
pub struct SecretString(String);

impl SecretString {
    /// Creates a new `SecretString` from any type that can be converted to a `String`.
    #[must_use]
    pub fn new(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    /// Exposes the secret value.
    ///
    /// Use this method only when you need to access the actual secret,
    /// such as when passing it to a hashing function.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Returns true if the secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the length of the secret in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl From<String> for SecretString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for SecretString {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for SecretString {}

impl Serialize for SecretString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Expose the actual value for serialization (e.g., returning tokens in API responses)
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(SecretString(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_string_debug_redacted() {
        let secret = SecretString::new("my_password");
        assert_eq!(format!("{secret:?}"), "SecretString([REDACTED])");
    }

    #[test]
    fn test_secret_string_display_redacted() {
        let secret = SecretString::new("my_password");
        assert_eq!(format!("{secret}"), "[REDACTED]");
    }

    #[test]
    fn test_secret_string_expose_secret() {
        let secret = SecretString::new("my_password");
        assert_eq!(secret.expose_secret(), "my_password");
    }

    #[test]
    fn test_secret_string_from_string() {
        let secret: SecretString = String::from("password").into();
        assert_eq!(secret.expose_secret(), "password");
    }

    #[test]
    fn test_secret_string_from_str() {
        let secret: SecretString = "password".into();
        assert_eq!(secret.expose_secret(), "password");
    }

    #[test]
    fn test_secret_string_serialize() {
        let secret = SecretString::new("my_token");
        let json = serde_json::to_string(&secret).unwrap();
        assert_eq!(json, "\"my_token\"");
    }

    #[test]
    fn test_secret_string_deserialize() {
        let json = "\"my_token\"";
        let secret: SecretString = serde_json::from_str(json).unwrap();
        assert_eq!(secret.expose_secret(), "my_token");
    }

    #[test]
    fn test_secret_string_roundtrip() {
        let original = SecretString::new("secret_value");
        let json = serde_json::to_string(&original).unwrap();
        let restored: SecretString = serde_json::from_str(&json).unwrap();
        assert_eq!(original, restored);
    }
}
