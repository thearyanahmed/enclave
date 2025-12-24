#![allow(clippy::unwrap_used)]

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::{Arc, Mutex};

use crate::crypto::SecretString;
use crate::AuthError;

use super::password_reset::{PasswordResetRepository, PasswordResetToken};

fn generate_token() -> SecretString {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let token: String = (0..32)
        .map(|_| char::from(rng.sample(rand::distributions::Alphanumeric)))
        .collect();
    SecretString::new(token)
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
        user_id: i32,
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
}
