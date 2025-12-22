use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::repository::CreateTokenOptions;
use crate::{AccessToken, AuthError, TokenRepository};

use super::JwtService;

/// JWT-based token provider that implements `TokenRepository`.
///
/// This allows using JWT tokens with existing handlers that expect `TokenRepository`.
/// Swap out your opaque token repository with this to use JWT instead.
///
/// # Example
///
/// ```ignore
/// use enclave::jwt::{JwtConfig, JwtService, JwtTokenProvider};
/// use enclave::actions::LoginAction;
///
/// let config = JwtConfig::new("your-secret-key");
/// let service = JwtService::new(config);
/// let jwt_provider = JwtTokenProvider::new(service);
///
/// // Use with existing LoginAction - same as with opaque tokens!
/// let login = LoginAction::new(user_repo, jwt_provider, rate_limiter);
/// let (user, token) = login.execute(email, password).await?;
/// ```
#[derive(Clone)]
pub struct JwtTokenProvider {
    service: JwtService,
}

impl JwtTokenProvider {
    /// Creates a new JWT token provider.
    pub fn new(service: JwtService) -> Self {
        Self { service }
    }
}

#[async_trait]
impl TokenRepository for JwtTokenProvider {
    async fn create_token(
        &self,
        user_id: i32,
        _expires_at: DateTime<Utc>,
    ) -> Result<AccessToken, AuthError> {
        self.create_token_with_options(user_id, _expires_at, CreateTokenOptions::default())
            .await
    }

    async fn create_token_with_options(
        &self,
        user_id: i32,
        _expires_at: DateTime<Utc>,
        options: CreateTokenOptions,
    ) -> Result<AccessToken, AuthError> {
        // Note: We ignore the provided expires_at and use the JWT config's expiry
        // This ensures consistency with JWT validation
        let token = self.service.encode(user_id)?;
        let now = Utc::now();
        let expires_at = now + self.service.expiry();

        let abilities = if options.abilities.is_empty() {
            vec!["*".to_owned()]
        } else {
            options.abilities
        };

        Ok(AccessToken {
            token,
            user_id,
            name: options.name,
            abilities,
            expires_at,
            created_at: now,
            last_used_at: None,
        })
    }

    async fn find_token(&self, token: &str) -> Result<Option<AccessToken>, AuthError> {
        match self.service.decode(token) {
            Ok(claims) => {
                let user_id = claims.user_id()?;
                let expires_at = DateTime::from_timestamp(claims.exp, 0)
                    .ok_or(AuthError::TokenInvalid)?;
                let created_at = DateTime::from_timestamp(claims.iat, 0)
                    .ok_or(AuthError::TokenInvalid)?;

                Ok(Some(AccessToken {
                    token: token.to_owned(),
                    user_id,
                    name: None,
                    abilities: vec!["*".to_owned()],
                    expires_at,
                    created_at,
                    last_used_at: None,
                }))
            }
            Err(AuthError::TokenExpired) => Err(AuthError::TokenExpired),
            Err(_) => Ok(None),
        }
    }

    async fn revoke_token(&self, _token: &str) -> Result<(), AuthError> {
        // JWT tokens are stateless - revocation requires a blocklist
        // which is outside the scope of basic JWT support.
        // For now, this is a no-op. Users who need revocation should
        // use short expiry times or implement their own blocklist.
        Ok(())
    }

    async fn revoke_all_user_tokens(&self, _user_id: i32) -> Result<(), AuthError> {
        // JWT tokens are stateless - cannot revoke all tokens without
        // tracking issued tokens or using a blocklist.
        // This is a no-op for basic JWT support.
        Ok(())
    }

    async fn touch_token(&self, _token: &str) -> Result<(), AuthError> {
        // JWT tokens are stateless - no last_used_at tracking
        Ok(())
    }

    async fn prune_expired(&self) -> Result<u64, AuthError> {
        // JWT tokens are stateless - no storage to prune
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::JwtConfig;

    #[tokio::test]
    async fn test_jwt_provider_create_and_find() {
        let config = JwtConfig::new("test-secret-key-32-bytes-long!!");
        let service = JwtService::new(config);
        let provider = JwtTokenProvider::new(service);

        let expires_at = Utc::now() + chrono::Duration::hours(1);
        let token = provider.create_token(42, expires_at).await.unwrap();
        assert_eq!(token.user_id, 42);
        assert!(!token.token.is_empty());

        let found = provider.find_token(&token.token).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().user_id, 42);
    }

    #[tokio::test]
    async fn test_jwt_provider_invalid_token() {
        let config = JwtConfig::new("test-secret-key-32-bytes-long!!");
        let service = JwtService::new(config);
        let provider = JwtTokenProvider::new(service);

        let result = provider.find_token("invalid-token").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_jwt_provider_revoke_is_noop() {
        let config = JwtConfig::new("test-secret-key-32-bytes-long!!");
        let service = JwtService::new(config);
        let provider = JwtTokenProvider::new(service);

        // Revoke should succeed (it's a no-op)
        let result = provider.revoke_token("any-token").await;
        assert!(result.is_ok());
    }
}
