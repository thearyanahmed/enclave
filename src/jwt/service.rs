use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};

use crate::AuthError;

use super::{JwtClaims, JwtConfig};

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

    /// Encodes a user ID into a JWT token.
    pub fn encode(&self, user_id: i32) -> Result<String, AuthError> {
        let now = Utc::now();
        let exp = now + self.config.expiry;

        let claims = JwtClaims {
            sub: user_id.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
        };

        jsonwebtoken::encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|_| AuthError::TokenInvalid)
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

    /// Validates a token and returns the user ID if valid.
    pub fn validate(&self, token: &str) -> Result<i32, AuthError> {
        let claims = self.decode(token)?;
        claims.user_id()
    }

    /// Returns the configured expiry duration.
    pub fn expiry(&self) -> Duration {
        self.config.expiry()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let config = JwtConfig::new("test-secret-key-32-bytes-long!!");
        let service = JwtService::new(config);

        let token = service.encode(42).unwrap();
        let claims = service.decode(&token).unwrap();

        assert_eq!(claims.user_id().unwrap(), 42);
    }

    #[test]
    fn test_invalid_token() {
        let config = JwtConfig::new("test-secret-key-32-bytes-long!!");
        let service = JwtService::new(config);

        let result = service.decode("invalid-token");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::TokenInvalid);
    }

    #[test]
    fn test_wrong_secret() {
        let config1 = JwtConfig::new("secret-one-32-bytes-long!!!!!!!!");
        let config2 = JwtConfig::new("secret-two-32-bytes-long!!!!!!!!");

        let service1 = JwtService::new(config1);
        let service2 = JwtService::new(config2);

        let token = service1.encode(42).unwrap();
        let result = service2.decode(&token);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::TokenInvalid);
    }

    #[test]
    fn test_expired_token() {
        let config = JwtConfig::new("test-secret-key-32-bytes-long!!")
            .with_expiry(Duration::seconds(-1)); // Already expired

        let service = JwtService::new(config);
        let token = service.encode(42).unwrap();

        let result = service.decode(&token);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::TokenExpired);
    }

    #[test]
    fn test_with_issuer_and_audience() {
        let config = JwtConfig::new("test-secret-key-32-bytes-long!!")
            .with_issuer("enclave")
            .with_audience("my-app");

        let service = JwtService::new(config);
        let token = service.encode(42).unwrap();
        let claims = service.decode(&token).unwrap();

        assert_eq!(claims.iss, Some("enclave".to_owned()));
        assert_eq!(claims.aud, Some("my-app".to_owned()));
    }
}
