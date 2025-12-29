#![allow(clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::password_reset::{PasswordResetRepository, PasswordResetToken};
use crate::{AuthError, SecretString};

fn generate_token() -> SecretString {
    SecretString::new(crate::crypto::generate_token(32))
}

#[derive(Clone)]
pub struct MockPasswordResetRepository {
    pub tokens: Arc<Mutex<Vec<PasswordResetToken>>>,
}

impl MockPasswordResetRepository {
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(Mutex::new(vec![])),
        }
    }
}

#[async_trait]
impl PasswordResetRepository for MockPasswordResetRepository {
    async fn create_reset_token(
        &self,
        user_id: u64,
        expires_at: DateTime<Utc>,
    ) -> Result<PasswordResetToken, AuthError> {
        let token = PasswordResetToken {
            token: generate_token(),
            user_id,
            expires_at,
            created_at: Utc::now(),
        };

        let mut tokens = self.tokens.lock().unwrap();
        tokens.push(token.clone());
        drop(tokens);

        Ok(token)
    }

    async fn find_reset_token(&self, token: &str) -> Result<Option<PasswordResetToken>, AuthError> {
        let tokens = self.tokens.lock().unwrap();
        Ok(tokens
            .iter()
            .find(|t| t.token.expose_secret() == token)
            .cloned())
    }

    async fn delete_reset_token(&self, token: &str) -> Result<(), AuthError> {
        let mut tokens = self.tokens.lock().unwrap();
        tokens.retain(|t| t.token.expose_secret() != token);
        drop(tokens);
        Ok(())
    }

    async fn prune_expired(&self) -> Result<u64, AuthError> {
        let mut tokens = self.tokens.lock().unwrap();
        let now = Utc::now();
        let before = tokens.len();
        tokens.retain(|t| t.expires_at > now);
        let removed = before - tokens.len();
        drop(tokens);
        Ok(u64::try_from(removed).unwrap_or(u64::MAX))
    }
}
