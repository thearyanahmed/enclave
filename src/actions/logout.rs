use crate::{AuthError, TokenRepository};

pub struct LogoutAction<T: TokenRepository> {
    token_repository: T,
}

impl<T: TokenRepository> LogoutAction<T> {
    pub fn new(token_repository: T) -> Self {
        Self { token_repository }
    }

    pub async fn execute(&self, token: &str) -> Result<(), AuthError> {
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

        let found = logout.token_repository.find_token(&token.token).await.unwrap();
        assert!(found.is_none());
    }
}
