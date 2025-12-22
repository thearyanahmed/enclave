use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::AuthError;

use super::rate_limiter::{LoginAttempt, RateLimiterRepository};

pub struct MockRateLimiterRepository {
    pub attempts: std::sync::Mutex<Vec<LoginAttempt>>,
}

impl MockRateLimiterRepository {
    pub fn new() -> Self {
        Self {
            attempts: std::sync::Mutex::new(vec![]),
        }
    }
}

#[async_trait]
impl RateLimiterRepository for MockRateLimiterRepository {
    async fn record_attempt(
        &self,
        email: &str,
        success: bool,
        ip_address: Option<&str>,
    ) -> Result<(), AuthError> {
        let attempt = LoginAttempt {
            email: email.to_owned(),
            success,
            ip_address: ip_address.map(ToOwned::to_owned),
            attempted_at: Utc::now(),
        };

        let mut attempts = self.attempts.lock().unwrap();
        attempts.push(attempt);
        drop(attempts);

        Ok(())
    }

    async fn get_recent_failed_attempts(
        &self,
        email: &str,
        since: DateTime<Utc>,
    ) -> Result<u32, AuthError> {
        let count = {
            let attempts = self.attempts.lock().unwrap();
            attempts
                .iter()
                .filter(|a| a.email == email && !a.success && a.attempted_at >= since)
                .count()
        };
        let count = u32::try_from(count).unwrap_or(u32::MAX);
        Ok(count)
    }

    async fn clear_attempts(&self, email: &str) -> Result<(), AuthError> {
        let mut attempts = self.attempts.lock().unwrap();
        attempts.retain(|a| a.email != email);
        drop(attempts);
        Ok(())
    }
}
