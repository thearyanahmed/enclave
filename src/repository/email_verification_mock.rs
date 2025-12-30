#![allow(clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::email_verification::{EmailVerificationRepository, EmailVerificationToken};
use crate::{AuthError, SecretString};

fn generate_token() -> SecretString {
    SecretString::new(crate::crypto::generate_token(32))
}

#[derive(Clone)]
pub struct MockEmailVerificationRepository {
    pub tokens: Arc<Mutex<Vec<EmailVerificationToken>>>,
}

impl MockEmailVerificationRepository {
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(Mutex::new(vec![])),
        }
    }
}

#[async_trait]
impl EmailVerificationRepository for MockEmailVerificationRepository {
    async fn create_verification_token(
        &self,
        user_id: i64,
        expires_at: DateTime<Utc>,
    ) -> Result<EmailVerificationToken, AuthError> {
        let token = EmailVerificationToken {
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

    async fn find_verification_token(
        &self,
        token: &str,
    ) -> Result<Option<EmailVerificationToken>, AuthError> {
        let tokens = self.tokens.lock().unwrap();
        Ok(tokens
            .iter()
            .find(|t| t.token.expose_secret() == token)
            .cloned())
    }

    async fn delete_verification_token(&self, token: &str) -> Result<(), AuthError> {
        let mut tokens = self.tokens.lock().unwrap();
        tokens.retain(|t| t.token.expose_secret() != token);
        drop(tokens);
        Ok(())
    }

    async fn prune_expired(&self) -> Result<i64, AuthError> {
        let mut tokens = self.tokens.lock().unwrap();
        let now = Utc::now();
        let before = tokens.len();
        tokens.retain(|t| t.expires_at > now);
        let removed = before - tokens.len();
        drop(tokens);
        #[allow(clippy::cast_possible_wrap, clippy::as_conversions)]
        Ok(removed as i64)
    }
}
