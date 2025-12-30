#![allow(clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::token::{AccessToken, CreateTokenOptions, StatefulTokenRepository, TokenRepository};
use crate::crypto::{generate_token_default, hash_token};
use crate::{AuthError, SecretString};

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
        user_id: i64,
        expires_at: DateTime<Utc>,
    ) -> Result<AccessToken, AuthError> {
        self.create_token_with_options(user_id, expires_at, CreateTokenOptions::default())
            .await
    }

    async fn create_token_with_options(
        &self,
        user_id: i64,
        expires_at: DateTime<Utc>,
        options: CreateTokenOptions,
    ) -> Result<AccessToken, AuthError> {
        let plain_token = generate_token_default();
        let hashed_token = hash_token(&plain_token);
        let now = Utc::now();

        let stored_token = AccessToken {
            token: SecretString::new(hashed_token),
            user_id,
            name: options.name.clone(),
            expires_at,
            created_at: now,
        };

        let mut tokens = self.tokens.lock().unwrap();
        tokens.push(stored_token);
        drop(tokens);

        Ok(AccessToken {
            token: SecretString::new(plain_token),
            user_id,
            name: options.name,
            expires_at,
            created_at: now,
        })
    }

    async fn find_token(&self, token: &str) -> Result<Option<AccessToken>, AuthError> {
        let hashed = hash_token(token);
        let tokens = self.tokens.lock().unwrap();
        Ok(tokens
            .iter()
            .find(|t| t.token.expose_secret() == hashed)
            .cloned())
    }
}

#[async_trait]
impl StatefulTokenRepository for MockTokenRepository {
    async fn revoke_token(&self, token: &str) -> Result<(), AuthError> {
        let hashed = hash_token(token);
        let mut tokens = self.tokens.lock().unwrap();
        tokens.retain(|t| t.token.expose_secret() != hashed);
        drop(tokens);
        Ok(())
    }

    async fn revoke_all_user_tokens(&self, user_id: i64) -> Result<(), AuthError> {
        let mut tokens = self.tokens.lock().unwrap();
        tokens.retain(|t| t.user_id != user_id);
        drop(tokens);
        Ok(())
    }

    async fn prune_expired(&self) -> Result<i64, AuthError> {
        let now = Utc::now();
        let mut tokens = self.tokens.lock().unwrap();
        let before = tokens.len();
        tokens.retain(|t| t.expires_at > now);
        let removed = before - tokens.len();
        drop(tokens);
        #[allow(clippy::cast_possible_wrap, clippy::as_conversions)]
        Ok(removed as i64)
    }
}
