use crate::{AuthError, TokenRepository};

#[cfg(feature = "tracing")]
use crate::TracingConfig;

pub struct LogoutAction<T: TokenRepository> {
    token_repository: T,
    #[cfg(feature = "tracing")]
    tracing: Option<TracingConfig>,
}

impl<T: TokenRepository> LogoutAction<T> {
    pub fn new(token_repository: T) -> Self {
        LogoutAction {
            token_repository,
            #[cfg(feature = "tracing")]
            tracing: None,
        }
    }

    #[cfg(feature = "tracing")]
    pub fn with_tracing(mut self) -> Self {
        self.tracing = Some(TracingConfig::new("logout"));
        self
    }

    #[cfg(feature = "tracing")]
    pub fn with_tracing_config(mut self, config: TracingConfig) -> Self {
        self.tracing = Some(config);
        self
    }

    pub async fn execute(&self, token: &str) -> Result<(), AuthError> {
        #[cfg(feature = "tracing")]
        {
            if let Some(ref config) = self.tracing {
                use tracing::Instrument;
                let span = tracing::info_span!("action", name = config.span_name);
                let result = self.token_repository.revoke_token(token).instrument(span).await;
                match &result {
                    Ok(()) => tracing::info!("logout successful"),
                    Err(e) => tracing::warn!(error = %e, "logout failed"),
                }
                return result;
            }
        }

        self.token_repository.revoke_token(token).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockTokenRepository;
    use chrono::{Duration, Utc};

    #[tokio::test]
    async fn test_logout_revokes_token() {
        let token_repo = MockTokenRepository::new();

        let expires_at = Utc::now() + Duration::days(7);
        let token = token_repo.create_token(1, expires_at).await.unwrap();

        let found = token_repo.find_token(&token.token).await.unwrap();
        assert!(found.is_some());

        let logout = LogoutAction::new(token_repo);
        let result = logout.execute(&token.token).await;
        assert!(result.is_ok());

        let found = logout
            .token_repository
            .find_token(&token.token)
            .await
            .unwrap();
        assert!(found.is_none());
    }
}
