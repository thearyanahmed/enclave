#![allow(clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::Utc;

use super::audit_log::{AuditEventType, AuditLog, AuditLogRepository};
use crate::AuthError;

#[derive(Clone)]
pub struct MockAuditLogRepository {
    pub logs: Arc<Mutex<Vec<AuditLog>>>,
    next_id: Arc<Mutex<i64>>,
}

impl MockAuditLogRepository {
    pub fn new() -> Self {
        Self {
            logs: Arc::new(Mutex::new(vec![])),
            next_id: Arc::new(Mutex::new(1)),
        }
    }
}

#[async_trait]
impl AuditLogRepository for MockAuditLogRepository {
    async fn log_event(
        &self,
        user_id: Option<i64>,
        event_type: AuditEventType,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        metadata: Option<&str>,
    ) -> Result<AuditLog, AuthError> {
        let id = {
            let mut next_id = self.next_id.lock().unwrap();
            let id = *next_id;
            *next_id += 1;
            id
        };

        let log = AuditLog {
            id,
            user_id,
            event_type,
            ip_address: ip_address.map(ToOwned::to_owned),
            user_agent: user_agent.map(ToOwned::to_owned),
            metadata: metadata.map(ToOwned::to_owned),
            created_at: Utc::now(),
        };

        let mut logs = self.logs.lock().unwrap();
        logs.push(log.clone());
        drop(logs);

        Ok(log)
    }

    async fn get_user_events(
        &self,
        user_id: i64,
        limit: usize,
    ) -> Result<Vec<AuditLog>, AuthError> {
        let user_logs = {
            let logs = self.logs.lock().unwrap();
            logs.iter()
                .filter(|l| l.user_id == Some(user_id))
                .rev()
                .take(limit)
                .cloned()
                .collect()
        };
        Ok(user_logs)
    }
}
