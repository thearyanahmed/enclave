use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::JwtService;
use crate::repository::CreateTokenOptions;
use crate::{AccessToken, AuthError, SecretString, TokenRepository};

/// JWT-based token provider that implements [`TokenRepository`].
///
/// This allows using JWT tokens with existing handlers that expect [`TokenRepository`].
/// Swap out your opaque token repository with this to use JWT instead.
///
/// Note: JWT tokens are stateless, so `revoke_token`, `touch_token`, and `prune_expired`
/// are no-ops. For true revocation, implement a blocklist.
///
/// [`TokenRepository`]: crate::TokenRepository
#[derive(Clone)]
pub struct JwtTokenProvider {
    service: JwtService,
}

impl JwtTokenProvider {
    pub fn new(service: JwtService) -> Self {
        Self { service }
    }
}

#[async_trait]
impl TokenRepository for JwtTokenProvider {
    async fn create_token(
        &self,
        user_id: u64,
        _expires_at: DateTime<Utc>,
    ) -> Result<AccessToken, AuthError> {
        self.create_token_with_options(user_id, _expires_at, CreateTokenOptions::default())
            .await
    }

    async fn create_token_with_options(
        &self,
        user_id: u64,
        _expires_at: DateTime<Utc>,
        options: CreateTokenOptions,
    ) -> Result<AccessToken, AuthError> {
        // Note: We ignore the provided expires_at and use the JWT config's expiry
        // This ensures consistency with JWT validation
        let token = self.service.encode(user_id)?;
        let now = Utc::now();
        let expires_at = now + self.service.expiry();

        Ok(AccessToken {
            token: SecretString::new(token),
            user_id,
            name: options.name,
            expires_at,
            created_at: now,
        })
    }

    async fn find_token(&self, token: &str) -> Result<Option<AccessToken>, AuthError> {
        match self.service.decode(token) {
            Ok(claims) => {
                let user_id = claims.user_id()?;
                let expires_at =
                    DateTime::from_timestamp(claims.exp, 0).ok_or(AuthError::TokenInvalid)?;
                let created_at =
                    DateTime::from_timestamp(claims.iat, 0).ok_or(AuthError::TokenInvalid)?;

                Ok(Some(AccessToken {
                    token: SecretString::new(token),
                    user_id,
                    name: None,
                    expires_at,
                    created_at,
                }))
            }
            Err(AuthError::TokenExpired) => Err(AuthError::TokenExpired),
            Err(_) => Ok(None),
        }
    }
}

// Note: JwtTokenProvider does NOT implement StatefulTokenRepository.
// JWT tokens are stateless - revocation, tracking, and cleanup are not applicable.
// For logout with JWT, the client should discard the token.
// For immediate invalidation, implement a token blocklist separately.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::JwtConfig;

    #[tokio::test]
    async fn test_jwt_provider_create_and_find() {
        let config = JwtConfig::new("test-secret-32-bytes-long-key-13").unwrap();
        let service = JwtService::new(config);
        let provider = JwtTokenProvider::new(service);

        let expires_at = Utc::now() + chrono::Duration::hours(1);
        let token = provider.create_token(42, expires_at).await.unwrap();
        assert_eq!(token.user_id, 42);
        assert!(!token.token.is_empty());

        let found = provider
            .find_token(token.token.expose_secret())
            .await
            .unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().user_id, 42);
    }

    #[tokio::test]
    async fn test_jwt_provider_invalid_token() {
        let config = JwtConfig::new("test-secret-32-bytes-long-key-13").unwrap();
        let service = JwtService::new(config);
        let provider = JwtTokenProvider::new(service);

        let result = provider.find_token("invalid-token").await.unwrap();
        assert!(result.is_none());
    }
}
