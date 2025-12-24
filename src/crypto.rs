use crate::AuthError;
use argon2::{Algorithm, Argon2, Params, PasswordVerifier, Version};
use password_hash::{PasswordHash, PasswordHasher as ArgonPasswordHasher, SaltString};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

/// Default token length in characters.
pub const DEFAULT_TOKEN_LENGTH: usize = 32;

/// Trait for password hashing and verification.
///
/// This trait allows pluggable password hashing implementations.
/// The default implementation is [`Argon2Hasher`].
///
/// # Example
///
/// ```rust
/// use enclave::crypto::{PasswordHasher, Argon2Hasher};
///
/// let hasher = Argon2Hasher::default();
/// let hash = hasher.hash("mypassword").unwrap();
/// assert!(hasher.verify("mypassword", &hash).unwrap());
/// assert!(!hasher.verify("wrongpassword", &hash).unwrap());
/// ```
pub trait PasswordHasher: Send + Sync {
    /// Hash a password.
    ///
    /// # Errors
    ///
    /// Returns `AuthError::PasswordHashError` if hashing fails.
    fn hash(&self, password: &str) -> Result<String, AuthError>;

    /// Verify a password against a hash.
    ///
    /// # Errors
    ///
    /// Returns `AuthError::PasswordHashError` if the hash is malformed.
    fn verify(&self, password: &str, hash: &str) -> Result<bool, AuthError>;
}

/// Argon2id password hasher with configurable parameters.
///
/// # Example
///
/// ```rust
/// use enclave::crypto::Argon2Hasher;
///
/// // Default settings (64 MiB memory, 3 iterations, 4 threads)
/// let hasher = Argon2Hasher::default();
///
/// // Production settings (OWASP 2024 recommendations)
/// let hasher = Argon2Hasher::production();
///
/// // Custom settings
/// let hasher = Argon2Hasher::new(32768, 4, 2);
/// ```
#[derive(Debug, Clone)]
pub struct Argon2Hasher {
    /// Memory cost in KiB
    memory_cost: u32,
    /// Number of iterations
    time_cost: u32,
    /// Degree of parallelism
    parallelism: u32,
}

impl Default for Argon2Hasher {
    fn default() -> Self {
        Self {
            memory_cost: 19456, // 19 MiB - argon2 default
            time_cost: 2,
            parallelism: 1,
        }
    }
}

impl Argon2Hasher {
    /// Creates a new hasher with custom parameters.
    ///
    /// # Arguments
    ///
    /// * `memory_cost` - Memory usage in KiB
    /// * `time_cost` - Number of iterations
    /// * `parallelism` - Number of threads
    #[must_use]
    pub fn new(memory_cost: u32, time_cost: u32, parallelism: u32) -> Self {
        Self {
            memory_cost,
            time_cost,
            parallelism,
        }
    }

    /// Production-recommended settings based on OWASP 2024 guidelines.
    ///
    /// Parameters: 64 MiB memory, 3 iterations, 4 threads.
    #[must_use]
    pub fn production() -> Self {
        Self {
            memory_cost: 65536, // 64 MiB
            time_cost: 3,
            parallelism: 4,
        }
    }
}

impl PasswordHasher for Argon2Hasher {
    fn hash(&self, password: &str) -> Result<String, AuthError> {
        let salt = SaltString::generate(&mut OsRng);
        let params = Params::new(self.memory_cost, self.time_cost, self.parallelism, None)
            .map_err(|_| AuthError::PasswordHashError)?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|_| AuthError::PasswordHashError)
    }

    fn verify(&self, password: &str, hash: &str) -> Result<bool, AuthError> {
        let parsed = PasswordHash::new(hash).map_err(|_| AuthError::PasswordHashError)?;

        // Verification uses params from the hash, not from config
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    }
}

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
