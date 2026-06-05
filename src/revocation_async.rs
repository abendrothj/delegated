use crate::revocation::{InMemoryTrustState, TrustStateAdmin, TrustStateError, TrustStateStore};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

/// Async counterpart to [`TrustStateStore`]. Implement against Redis, PostgreSQL,
/// DynamoDB, or any shared store.
///
/// All methods take `&self` — implementations must use interior mutability
/// (e.g. `Mutex`, `DashMap`, or a database transaction).
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

/// Async admin operations.
///
/// Default implementations are provided for `revoke_tokens` (loops over
/// `revoke_token`) and `flush_expired_nonces` (no-op, suitable for backends
/// that handle expiry externally, e.g. Redis `EXAT`).
#[async_trait]
pub trait AsyncTrustStateAdmin: AsyncTrustStateStore {
    async fn revoke_token(&self, token_id: &str) -> Result<(), TrustStateError>;
    async fn emergency_deny_agent(&self, agent_id: &str) -> Result<(), TrustStateError>;
    /// Clear all entries from the emergency deny list. Returns count removed.
    async fn clear_emergency_deny_list(&self) -> Result<u64, TrustStateError>;

    /// Revoke multiple tokens. Returns the count revoked.
    async fn revoke_tokens(&self, token_ids: &[&str]) -> Result<u64, TrustStateError> {
        let mut count = 0u64;
        for id in token_ids {
            self.revoke_token(id).await?;
            count += 1;
        }
        Ok(count)
    }

    /// Flush consumed nonces that have expired as of `reference_time`.
    /// The default is a no-op for backends that handle expiry externally.
    async fn flush_expired_nonces(
        &self,
        _reference_time: DateTime<Utc>,
    ) -> Result<u64, TrustStateError> {
        Ok(0)
    }
}

/// In-memory async trust state.
///
/// Wraps [`InMemoryTrustState`], which already uses interior mutability, so no
/// additional locking is required. Suitable for tests and single-process
/// deployments. For multi-process or high-throughput production use, implement
/// [`AsyncTrustStateStore`] against a shared store (Redis, PostgreSQL, etc.).
pub struct InMemoryAsyncTrustState {
    inner: InMemoryTrustState,
}

impl InMemoryAsyncTrustState {
    pub fn new() -> Self {
        Self {
            inner: InMemoryTrustState::new(),
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
        TrustStateStore::is_token_revoked(&self.inner, token_id)
    }

    async fn is_agent_emergency_denied(&self, agent_id: &str) -> Result<bool, TrustStateError> {
        TrustStateStore::is_agent_emergency_denied(&self.inner, agent_id)
    }

    async fn consume_nonce(
        &self,
        nonce: &str,
        valid_until: DateTime<Utc>,
    ) -> Result<bool, TrustStateError> {
        TrustStateStore::consume_nonce(&self.inner, nonce, valid_until)
    }
}

#[async_trait]
impl AsyncTrustStateAdmin for InMemoryAsyncTrustState {
    async fn revoke_token(&self, token_id: &str) -> Result<(), TrustStateError> {
        TrustStateAdmin::revoke_token(&self.inner, token_id)
    }

    async fn emergency_deny_agent(&self, agent_id: &str) -> Result<(), TrustStateError> {
        TrustStateAdmin::emergency_deny_agent(&self.inner, agent_id)
    }

    async fn clear_emergency_deny_list(&self) -> Result<u64, TrustStateError> {
        TrustStateAdmin::clear_emergency_deny_list(&self.inner)
    }

    async fn flush_expired_nonces(
        &self,
        reference_time: DateTime<Utc>,
    ) -> Result<u64, TrustStateError> {
        TrustStateAdmin::flush_expired_nonces(&self.inner, reference_time)
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
    async fn async_nonce_replay_is_blocked_with_mixed_expiries() {
        let state = InMemoryAsyncTrustState::new();
        let now = Utc::now();
        let first_expiry = now + chrono::Duration::minutes(5);
        let second_expiry = now + chrono::Duration::minutes(30);

        assert!(
            state
                .consume_nonce("nonce-short", first_expiry)
                .await
                .expect("first consume should succeed")
        );
        assert!(
            state
                .consume_nonce("nonce-long", second_expiry)
                .await
                .expect("different nonce should succeed")
        );
        assert!(
            !state
                .consume_nonce("nonce-short", first_expiry)
                .await
                .expect("replay of first nonce should be blocked")
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

    #[tokio::test]
    async fn async_bulk_revoke_and_clear_emergency_list() {
        let state = InMemoryAsyncTrustState::new();
        let ids = ["dlg_x", "dlg_y"];
        let count = state
            .revoke_tokens(&ids)
            .await
            .expect("bulk revoke should succeed");
        assert_eq!(count, 2);
        for id in &ids {
            assert!(
                state
                    .is_token_revoked(id)
                    .await
                    .expect("query should succeed")
            );
        }

        state
            .emergency_deny_agent("agent:bad")
            .await
            .expect("deny should succeed");
        let cleared = state
            .clear_emergency_deny_list()
            .await
            .expect("clear should succeed");
        assert_eq!(cleared, 1);
        assert!(
            !state
                .is_agent_emergency_denied("agent:bad")
                .await
                .expect("query should succeed")
        );
    }
}
