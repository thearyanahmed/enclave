use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};

use super::{JwtClaims, JwtConfig, TokenType};
use crate::AuthError;
use crate::crypto::generate_token;

/// Length of the JWT ID (jti) in bytes.
const JTI_LENGTH: usize = 16;

/// A pair of access and refresh tokens.
#[derive(Debug, Clone)]
pub struct TokenPair {
    /// Short-lived access token for API requests.
    pub access_token: String,
    /// Long-lived refresh token for obtaining new access tokens.
    pub refresh_token: String,
    /// Access token expiry in seconds.
    pub expires_in: i64,
}

/// Service for encoding and decoding JWT tokens.
#[derive(Clone)]
pub struct JwtService {
    config: JwtConfig,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl JwtService {
    /// Creates a new JWT service with the given configuration.
    pub fn new(config: JwtConfig) -> Self {
        let encoding_key = EncodingKey::from_secret(config.secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(config.secret.as_bytes());

        Self {
            config,
            encoding_key,
            decoding_key,
        }
    }

    /// Encodes a user ID into an access token.
    pub fn encode(&self, user_id: i32) -> Result<String, AuthError> {
        self.encode_access_token(user_id)
    }

    /// Encodes a user ID into a short-lived access token.
    pub fn encode_access_token(&self, user_id: i32) -> Result<String, AuthError> {
        let now = Utc::now();
        let exp = now + self.config.access_expiry();
        let jti = generate_token(JTI_LENGTH);

        let claims = JwtClaims {
            sub: user_id.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            jti,
            token_type: TokenType::Access,
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
        };

        jsonwebtoken::encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|_| AuthError::TokenInvalid)
    }

    /// Encodes a user ID into a long-lived refresh token.
    pub fn encode_refresh_token(&self, user_id: i32) -> Result<String, AuthError> {
        let now = Utc::now();
        let exp = now + self.config.refresh_expiry();
        let jti = generate_token(JTI_LENGTH);

        let claims = JwtClaims {
            sub: user_id.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            jti,
            token_type: TokenType::Refresh,
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
        };

        jsonwebtoken::encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|_| AuthError::TokenInvalid)
    }

    /// Creates both an access token and a refresh token for a user.
    pub fn create_token_pair(&self, user_id: i32) -> Result<TokenPair, AuthError> {
        let access_token = self.encode_access_token(user_id)?;
        let refresh_token = self.encode_refresh_token(user_id)?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            expires_in: self.config.access_expiry().num_seconds(),
        })
    }

    /// Exchanges a valid refresh token for a new access token.
    ///
    /// Returns an error if the token is invalid, expired, or not a refresh token.
    pub fn refresh_access_token(&self, refresh_token: &str) -> Result<String, AuthError> {
        let claims = self.decode(refresh_token)?;

        if !claims.is_refresh_token() {
            return Err(AuthError::TokenInvalid);
        }

        let user_id = claims.user_id()?;
        self.encode_access_token(user_id)
    }

    /// Exchanges a valid refresh token for a new token pair (access + refresh).
    ///
    /// This is useful for implementing refresh token rotation.
    pub fn rotate_tokens(&self, refresh_token: &str) -> Result<TokenPair, AuthError> {
        let claims = self.decode(refresh_token)?;

        if !claims.is_refresh_token() {
            return Err(AuthError::TokenInvalid);
        }

        let user_id = claims.user_id()?;
        self.create_token_pair(user_id)
    }

    /// Decodes and validates a JWT token, returning the claims.
    pub fn decode(&self, token: &str) -> Result<JwtClaims, AuthError> {
        let mut validation = Validation::new(Algorithm::HS256);

        if let Some(ref iss) = self.config.issuer {
            validation.set_issuer(&[iss]);
        }

        if let Some(ref aud) = self.config.audience {
            validation.set_audience(&[aud]);
        }

        let token_data = jsonwebtoken::decode::<JwtClaims>(token, &self.decoding_key, &validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                _ => AuthError::TokenInvalid,
            })?;

        Ok(token_data.claims)
    }

    /// Validates an access token and returns the user ID if valid.
    ///
    /// Returns an error if the token is a refresh token.
    pub fn validate(&self, token: &str) -> Result<i32, AuthError> {
        let claims = self.decode(token)?;

        // Only accept access tokens for validation
        if !claims.is_access_token() {
            return Err(AuthError::TokenInvalid);
        }

        claims.user_id()
    }

    /// Validates any token (access or refresh) and returns the user ID if valid.
    pub fn validate_any(&self, token: &str) -> Result<i32, AuthError> {
        let claims = self.decode(token)?;
        claims.user_id()
    }

    /// Returns the configured access token expiry duration.
    pub fn expiry(&self) -> Duration {
        self.config.expiry()
    }

    /// Returns the configured access token expiry duration.
    pub fn access_expiry(&self) -> Duration {
        self.config.access_expiry()
    }

    /// Returns the configured refresh token expiry duration.
    pub fn refresh_expiry(&self) -> Duration {
        self.config.refresh_expiry()
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::Header;

    use super::*;

    #[test]
    fn test_encode_decode() {
        let config = JwtConfig::new("test-secret-32-bytes-long-key-01").unwrap();
        let service = JwtService::new(config);

        let token = service.encode(42).unwrap();
        let claims = service.decode(&token).unwrap();

        assert_eq!(claims.user_id().unwrap(), 42);
    }

    #[test]
    fn test_invalid_token() {
        let config = JwtConfig::new("test-secret-32-bytes-long-key-02").unwrap();
        let service = JwtService::new(config);

        let result = service.decode("invalid-token");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::TokenInvalid);
    }

    #[test]
    fn test_wrong_secret() {
        let config1 = JwtConfig::new("test-secret-32-bytes-long-key-03").unwrap();
        let config2 = JwtConfig::new("test-secret-32-bytes-long-key-04").unwrap();

        let service1 = JwtService::new(config1);
        let service2 = JwtService::new(config2);

        let token = service1.encode(42).unwrap();
        let result = service2.decode(&token);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::TokenInvalid);
    }

    #[test]
    fn test_expired_token() {
        let config = JwtConfig::new("test-secret-32-bytes-long-key-05").unwrap();
        let service = JwtService::new(config);

        // Manually create an expired token
        let claims = JwtClaims {
            sub: "42".to_owned(),
            exp: Utc::now().timestamp() - 3600, // 1 hour in the past
            iat: Utc::now().timestamp() - 7200,
            jti: "test-jti".to_owned(),
            token_type: TokenType::Access,
            iss: None,
            aud: None,
        };

        let encoding_key = EncodingKey::from_secret(b"test-secret-32-bytes-long-key-05");
        let token = jsonwebtoken::encode(&Header::default(), &claims, &encoding_key).unwrap();

        let result = service.decode(&token);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::TokenExpired);
    }

    #[test]
    fn test_with_issuer_and_audience() {
        let config = JwtConfig::new("test-secret-32-bytes-long-key-06")
            .unwrap()
            .with_issuer("enclave")
            .with_audience("my-app");

        let service = JwtService::new(config);
        let token = service.encode(42).unwrap();
        let claims = service.decode(&token).unwrap();

        assert_eq!(claims.iss, Some("enclave".to_owned()));
        assert_eq!(claims.aud, Some("my-app".to_owned()));
    }

    #[test]
    fn test_token_pair() {
        let config = JwtConfig::new("test-secret-32-bytes-long-key-07").unwrap();
        let service = JwtService::new(config);

        let pair = service.create_token_pair(42).unwrap();

        // Verify access token
        let access_claims = service.decode(&pair.access_token).unwrap();
        assert_eq!(access_claims.user_id().unwrap(), 42);
        assert!(access_claims.is_access_token());

        // Verify refresh token
        let refresh_claims = service.decode(&pair.refresh_token).unwrap();
        assert_eq!(refresh_claims.user_id().unwrap(), 42);
        assert!(refresh_claims.is_refresh_token());
    }

    #[test]
    fn test_refresh_access_token() {
        let config = JwtConfig::new("test-secret-32-bytes-long-key-08").unwrap();
        let service = JwtService::new(config);

        let pair = service.create_token_pair(42).unwrap();

        // Refresh using refresh token should work
        let new_access = service.refresh_access_token(&pair.refresh_token).unwrap();
        let claims = service.decode(&new_access).unwrap();
        assert_eq!(claims.user_id().unwrap(), 42);
        assert!(claims.is_access_token());

        // Refresh using access token should fail
        let result = service.refresh_access_token(&pair.access_token);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::TokenInvalid);
    }

    #[test]
    fn test_validate_rejects_refresh_token() {
        let config = JwtConfig::new("test-secret-32-bytes-long-key-09").unwrap();
        let service = JwtService::new(config);

        let pair = service.create_token_pair(42).unwrap();

        // validate() should accept access token
        let user_id = service.validate(&pair.access_token).unwrap();
        assert_eq!(user_id, 42);

        // validate() should reject refresh token
        let result = service.validate(&pair.refresh_token);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::TokenInvalid);
    }

    #[test]
    fn test_rotate_tokens() {
        let config = JwtConfig::new("test-secret-32-bytes-long-key-10").unwrap();
        let service = JwtService::new(config);

        let pair = service.create_token_pair(42).unwrap();
        let new_pair = service.rotate_tokens(&pair.refresh_token).unwrap();

        // New tokens should be valid
        assert!(service.validate(&new_pair.access_token).is_ok());
        let refresh_claims = service.decode(&new_pair.refresh_token).unwrap();
        assert!(refresh_claims.is_refresh_token());

        // Rotating with access token should fail
        let result = service.rotate_tokens(&pair.access_token);
        assert!(result.is_err());
    }

    #[test]
    fn test_secret_too_short() {
        let result = JwtConfig::new("short");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, AuthError::ConfigurationError(ref msg) if msg.contains("32 bytes")),
            "Expected ConfigurationError with '32 bytes' message"
        );
    }

    #[test]
    fn test_jti_unique() {
        let config = JwtConfig::new("test-secret-32-bytes-long-key-11").unwrap();
        let service = JwtService::new(config);

        let token1 = service.encode(42).unwrap();
        let token2 = service.encode(42).unwrap();

        let claims1 = service.decode(&token1).unwrap();
        let claims2 = service.decode(&token2).unwrap();

        // Each token should have a unique jti
        assert_ne!(claims1.jti(), claims2.jti());
        assert!(!claims1.jti().is_empty());
        assert!(!claims2.jti().is_empty());
    }

    #[test]
    fn test_token_pair_unique_jti() {
        let config = JwtConfig::new("test-secret-32-bytes-long-key-12").unwrap();
        let service = JwtService::new(config);

        let pair = service.create_token_pair(42).unwrap();

        let access_claims = service.decode(&pair.access_token).unwrap();
        let refresh_claims = service.decode(&pair.refresh_token).unwrap();

        // Access and refresh tokens should have different jti
        assert_ne!(access_claims.jti(), refresh_claims.jti());
    }
}
