#![allow(clippy::unwrap_used)]

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::{Arc, Mutex};

use crate::AuthError;
use crate::crypto::hash_token;

use super::token::{AccessToken, TokenRepository};

fn generate_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|_| char::from(rng.sample(rand::distributions::Alphanumeric)))
        .collect()
}

#[derive(Clone)]
pub struct MockTokenRepository {
    pub tokens: Arc<Mutex<Vec<AccessToken>>>,
}

impl MockTokenRepository {
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(Mutex::new(vec![])),
        }
    }
}

#[async_trait]
impl TokenRepository for MockTokenRepository {
    async fn create_token(
        &self,
        user_id: i32,
        expires_at: DateTime<Utc>,
    ) -> Result<AccessToken, AuthError> {
        let plain_token = generate_token();
        let hashed_token = hash_token(&plain_token);
        let now = Utc::now();

        let stored_token = AccessToken {
            token: hashed_token,
            user_id,
            expires_at,
            created_at: now,
        };

        let mut tokens = self.tokens.lock().unwrap();
        tokens.push(stored_token);
        drop(tokens);

        Ok(AccessToken {
            token: plain_token,
            user_id,
            expires_at,
            created_at: now,
        })
    }

    async fn find_token(&self, token: &str) -> Result<Option<AccessToken>, AuthError> {
        let hashed = hash_token(token);
        let tokens = self.tokens.lock().unwrap();
        Ok(tokens.iter().find(|t| t.token == hashed).cloned())
    }

    async fn revoke_token(&self, token: &str) -> Result<(), AuthError> {
        let hashed = hash_token(token);
        let mut tokens = self.tokens.lock().unwrap();
        tokens.retain(|t| t.token != hashed);
        drop(tokens);
        Ok(())
    }

    async fn revoke_all_user_tokens(&self, user_id: i32) -> Result<(), AuthError> {
        let mut tokens = self.tokens.lock().unwrap();
        tokens.retain(|t| t.user_id != user_id);
        drop(tokens);
        Ok(())
    }
}
