use sha2::{Digest, Sha256};

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
