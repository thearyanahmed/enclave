use sha2::{Digest, Sha256};

/// Default token length in characters.
pub const DEFAULT_TOKEN_LENGTH: usize = 32;

/// Generates a cryptographically secure random token.
///
/// The token consists of alphanumeric characters (a-z, A-Z, 0-9),
/// providing approximately 5.95 bits of entropy per character.
///
/// # Arguments
///
/// * `length` - The number of characters in the token. Default is 32.
///
/// # Example
///
/// ```rust
/// use enclave::crypto::generate_token;
///
/// let token = generate_token(32);
/// assert_eq!(token.len(), 32);
/// ```
pub fn generate_token(length: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| char::from(rng.sample(rand::distributions::Alphanumeric)))
        .collect()
}

/// Generates a token with the default length (32 characters).
///
/// This is a convenience function that calls `generate_token(DEFAULT_TOKEN_LENGTH)`.
pub fn generate_token_default() -> String {
    generate_token(DEFAULT_TOKEN_LENGTH)
}

/// Hashes a token using SHA-256 for secure storage.
/// Unlike passwords, tokens are high-entropy random strings,
/// so a fast hash like SHA-256 is appropriate.
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_token_length() {
        let token = generate_token(32);
        assert_eq!(token.len(), 32);

        let token = generate_token(48);
        assert_eq!(token.len(), 48);

        let token = generate_token(64);
        assert_eq!(token.len(), 64);
    }

    #[test]
    fn test_generate_token_unique() {
        let token1 = generate_token(32);
        let token2 = generate_token(32);
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_generate_token_alphanumeric() {
        let token = generate_token(100);
        assert!(token.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_generate_token_default() {
        let token = generate_token_default();
        assert_eq!(token.len(), DEFAULT_TOKEN_LENGTH);
    }

    #[test]
    fn test_hash_token_deterministic() {
        let token = "abc123";
        let hash1 = hash_token(token);
        let hash2 = hash_token(token);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_token_different_inputs() {
        let hash1 = hash_token("token1");
        let hash2 = hash_token("token2");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_token_length() {
        let hash = hash_token("anytoken");
        // SHA-256 produces 64 hex characters
        assert_eq!(hash.len(), 64);
    }
}
