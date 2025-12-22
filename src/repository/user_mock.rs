#![allow(clippy::unwrap_used)]

use async_trait::async_trait;
use chrono::Utc;
use std::sync::{Arc, Mutex};

use crate::AuthError;

use super::user::{User, UserRepository};

#[derive(Clone)]
pub struct MockUserRepository {
    pub users: Arc<Mutex<Vec<User>>>,
}

impl MockUserRepository {
    pub fn new() -> Self {
        Self {
            users: Arc::new(Mutex::new(vec![])),
        }
    }
}

#[async_trait]
impl UserRepository for MockUserRepository {
    async fn find_user_by_id(&self, id: i32) -> Result<Option<User>, AuthError> {
        let users = self.users.lock().unwrap();
        Ok(users.iter().find(|u| u.id == id).cloned())
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, AuthError> {
        let users = self.users.lock().unwrap();
        Ok(users.iter().find(|u| u.email == email).cloned())
    }

    async fn create_user(&self, email: &str, hashed_password: &str) -> Result<User, AuthError> {
        let user = User::mock_from_credentials(email, hashed_password);

        let mut users = self.users.lock().unwrap();
        users.push(user.clone());
        drop(users);

        Ok(user)
    }

    async fn update_password(&self, user_id: i32, hashed_password: &str) -> Result<(), AuthError> {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.iter_mut().find(|u| u.id == user_id) {
            hashed_password.clone_into(&mut user.hashed_password);
            user.updated_at = Utc::now();
            Ok(())
        } else {
            Err(AuthError::UserNotFound)
        }
    }

    async fn verify_email(&self, user_id: i32) -> Result<(), AuthError> {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.iter_mut().find(|u| u.id == user_id) {
            user.email_verified_at = Some(Utc::now());
            user.updated_at = Utc::now();
            Ok(())
        } else {
            Err(AuthError::UserNotFound)
        }
    }

    async fn update_user(&self, user_id: i32, name: &str, email: &str) -> Result<User, AuthError> {
        let mut users = self.users.lock().unwrap();
        if let Some(user) = users.iter_mut().find(|u| u.id == user_id) {
            name.clone_into(&mut user.name);
            email.clone_into(&mut user.email);
            user.updated_at = Utc::now();
            Ok(user.clone())
        } else {
            Err(AuthError::UserNotFound)
        }
    }

    async fn delete_user(&self, user_id: i32) -> Result<(), AuthError> {
        let mut users = self.users.lock().unwrap();
        let len_before = users.len();
        users.retain(|u| u.id != user_id);
        if users.len() < len_before {
            Ok(())
        } else {
            Err(AuthError::UserNotFound)
        }
    }
}
