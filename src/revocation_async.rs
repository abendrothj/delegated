use crate::revocation::{InMemoryTrustState, TrustStateAdmin, TrustStateError, TrustStateStore};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::Mutex;

/// Async counterpart to [`TrustStateStore`]. Implement against Redis, PostgreSQL,
/// DynamoDB, or any shared store.
///
/// Note: `consume_nonce` takes `&self` (not `&mut self`) because async implementations
/// must use interior mutability (e.g. `Mutex`, `DashMap`, or a database transaction).
#[async_trait]
pub trait AsyncTrustStateStore: Send + Sync {
    async fn is_token_revoked(&self, token_id: &str) -> Result<bool, TrustStateError>;
    async fn is_agent_emergency_denied(&self, agent_id: &str) -> Result<bool, TrustStateError>;
    async fn consume_nonce(
        &self,
        nonce: &str,
        valid_until: DateTime<Utc>,
    ) -> Result<bool, TrustStateError>;
}

/// Async admin operations. Implementations must use interior mutability.
#[async_trait]
pub trait AsyncTrustStateAdmin: AsyncTrustStateStore {
    async fn revoke_token(&self, token_id: &str) -> Result<(), TrustStateError>;
    async fn emergency_deny_agent(&self, agent_id: &str) -> Result<(), TrustStateError>;
}

/// In-memory async trust state backed by `Mutex<InMemoryTrustState>`.
///
/// Suitable for tests and single-process deployments. For multi-process or
/// high-throughput production use, implement [`AsyncTrustStateStore`] against a
/// shared store (Redis, PostgreSQL, etc.).
pub struct InMemoryAsyncTrustState {
    inner: Mutex<InMemoryTrustState>,
}

impl InMemoryAsyncTrustState {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(InMemoryTrustState::new()),
        }
    }
}

impl Default for InMemoryAsyncTrustState {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AsyncTrustStateStore for InMemoryAsyncTrustState {
    async fn is_token_revoked(&self, token_id: &str) -> Result<bool, TrustStateError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| TrustStateError::new("async trust state mutex poisoned"))?;
        TrustStateStore::is_token_revoked(&*inner, token_id)
    }

    async fn is_agent_emergency_denied(&self, agent_id: &str) -> Result<bool, TrustStateError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| TrustStateError::new("async trust state mutex poisoned"))?;
        TrustStateStore::is_agent_emergency_denied(&*inner, agent_id)
    }

    async fn consume_nonce(
        &self,
        nonce: &str,
        valid_until: DateTime<Utc>,
    ) -> Result<bool, TrustStateError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| TrustStateError::new("async trust state mutex poisoned"))?;
        TrustStateStore::consume_nonce(&mut *inner, nonce, valid_until)
    }
}

#[async_trait]
impl AsyncTrustStateAdmin for InMemoryAsyncTrustState {
    async fn revoke_token(&self, token_id: &str) -> Result<(), TrustStateError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| TrustStateError::new("async trust state mutex poisoned"))?;
        TrustStateAdmin::revoke_token(&mut *inner, token_id)
    }

    async fn emergency_deny_agent(&self, agent_id: &str) -> Result<(), TrustStateError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| TrustStateError::new("async trust state mutex poisoned"))?;
        TrustStateAdmin::emergency_deny_agent(&mut *inner, agent_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn valid_until() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0)
            .single()
            .expect("valid timestamp")
    }

    #[tokio::test]
    async fn async_nonce_replay_is_blocked() {
        let state = InMemoryAsyncTrustState::new();
        assert!(
            state
                .consume_nonce("nonce-1", valid_until())
                .await
                .expect("first consume should succeed")
        );
        assert!(
            !state
                .consume_nonce("nonce-1", valid_until())
                .await
                .expect("second consume should be blocked")
        );
    }

    #[tokio::test]
    async fn async_revocation_persists_in_memory() {
        let state = InMemoryAsyncTrustState::new();
        state
            .revoke_token("dlg_abc")
            .await
            .expect("revoke should succeed");
        assert!(
            state
                .is_token_revoked("dlg_abc")
                .await
                .expect("query should succeed")
        );
        assert!(
            !state
                .is_token_revoked("dlg_other")
                .await
                .expect("query should succeed")
        );
    }

    #[tokio::test]
    async fn async_emergency_deny_blocks_agent() {
        let state = InMemoryAsyncTrustState::new();
        state
            .emergency_deny_agent("agent:bad")
            .await
            .expect("deny should succeed");
        assert!(
            state
                .is_agent_emergency_denied("agent:bad")
                .await
                .expect("query should succeed")
        );
        assert!(
            !state
                .is_agent_emergency_denied("agent:good")
                .await
                .expect("query should succeed")
        );
    }
}
