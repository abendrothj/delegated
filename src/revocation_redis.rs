use crate::revocation::{TrustStateAdmin, TrustStateError, TrustStateStore};
use crate::revocation_async::{AsyncTrustStateAdmin, AsyncTrustStateStore};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use redis::aio::ConnectionManager;

/// Shared-store implementation of [`AsyncTrustStateStore`] backed by Redis.
///
/// Each field uses a namespaced key so multiple `delegated` deployments can
/// share a single Redis instance without collisions. The default prefix is
/// `"delegated"`, producing keys like `delegated:nonce:{nonce}`.
///
/// **Nonce expiry** uses Redis `EXAT` (Redis ≥ 6.2), so nonce keys are
/// automatically evicted when the associated token expires — no background
/// sweeper needed.
///
/// **Revocation and deny-list entries** are permanent until removed via the
/// admin interface (`revoke_token`, `emergency_deny_agent`). There is no TTL
/// because revoking a token should remain in effect even after the token's
/// nominal expiry, to guard against clock skew at remote validators.
pub struct RedisTrustStateStore {
    conn: ConnectionManager,
    prefix: String,
}

impl RedisTrustStateStore {
    /// Connect using the given Redis URL (e.g. `redis://127.0.0.1:6379`).
    /// Uses the default key prefix `"delegated"`.
    pub async fn connect(url: &str) -> Result<Self, redis::RedisError> {
        Self::connect_with_prefix(url, "delegated").await
    }

    /// Connect with a custom key prefix. Useful when multiple services share
    /// one Redis instance and need isolated key namespaces.
    pub async fn connect_with_prefix(
        url: &str,
        prefix: &str,
    ) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(url)?;
        let conn = ConnectionManager::new(client).await?;
        Ok(Self {
            conn,
            prefix: prefix.to_string(),
        })
    }

    fn nonce_key(&self, nonce: &str) -> String {
        format!("{}:nonce:{}", self.prefix, nonce)
    }

    fn revoked_key(&self, token_id: &str) -> String {
        format!("{}:revoked:{}", self.prefix, token_id)
    }

    fn denied_key(&self, agent_id: &str) -> String {
        format!("{}:denied:{}", self.prefix, agent_id)
    }
}

#[async_trait]
impl AsyncTrustStateStore for RedisTrustStateStore {
    async fn is_token_revoked(&self, token_id: &str) -> Result<bool, TrustStateError> {
        let mut conn = self.conn.clone();
        let exists: bool = redis::cmd("EXISTS")
            .arg(self.revoked_key(token_id))
            .query_async(&mut conn)
            .await
            .map_err(|e| TrustStateError::new(format!("redis error: {e}")))?;
        Ok(exists)
    }

    async fn is_agent_emergency_denied(&self, agent_id: &str) -> Result<bool, TrustStateError> {
        let mut conn = self.conn.clone();
        let exists: bool = redis::cmd("EXISTS")
            .arg(self.denied_key(agent_id))
            .query_async(&mut conn)
            .await
            .map_err(|e| TrustStateError::new(format!("redis error: {e}")))?;
        Ok(exists)
    }

    async fn consume_nonce(
        &self,
        nonce: &str,
        valid_until: DateTime<Utc>,
    ) -> Result<bool, TrustStateError> {
        let mut conn = self.conn.clone();
        let unix_ts = valid_until.timestamp();
        // SET key 1 NX EXAT <unix_ts>
        // Returns "OK" if key was set (nonce is fresh), nil if it already existed (replay).
        let result: Option<String> = redis::cmd("SET")
            .arg(self.nonce_key(nonce))
            .arg("1")
            .arg("NX")
            .arg("EXAT")
            .arg(unix_ts)
            .query_async(&mut conn)
            .await
            .map_err(|e| TrustStateError::new(format!("redis error: {e}")))?;
        Ok(result.is_some())
    }
}

#[async_trait]
impl AsyncTrustStateAdmin for RedisTrustStateStore {
    async fn revoke_token(&self, token_id: &str) -> Result<(), TrustStateError> {
        let mut conn = self.conn.clone();
        redis::cmd("SET")
            .arg(self.revoked_key(token_id))
            .arg("1")
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| TrustStateError::new(format!("redis error: {e}")))
    }

    async fn emergency_deny_agent(&self, agent_id: &str) -> Result<(), TrustStateError> {
        let mut conn = self.conn.clone();
        redis::cmd("SET")
            .arg(self.denied_key(agent_id))
            .arg("1")
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| TrustStateError::new(format!("redis error: {e}")))
    }
}

/// Remove a revocation entry — call this if a token was revoked by mistake
/// and has not yet expired. This is an admin-only operation; use with care.
pub async fn unrevoke_token(
    store: &RedisTrustStateStore,
    token_id: &str,
) -> Result<(), TrustStateError> {
    let mut conn = store.conn.clone();
    redis::cmd("DEL")
        .arg(store.revoked_key(token_id))
        .query_async::<()>(&mut conn)
        .await
        .map_err(|e| TrustStateError::new(format!("redis error: {e}")))
}

/// Remove an emergency deny entry — call this to re-allow an agent that was
/// previously blocked. This is an admin-only operation; use with care.
pub async fn undeny_agent(
    store: &RedisTrustStateStore,
    agent_id: &str,
) -> Result<(), TrustStateError> {
    let mut conn = store.conn.clone();
    redis::cmd("DEL")
        .arg(store.denied_key(agent_id))
        .query_async::<()>(&mut conn)
        .await
        .map_err(|e| TrustStateError::new(format!("redis error: {e}")))
}

// Sync TrustStateStore/Admin are not implemented for RedisTrustStateStore — the
// async variants are the correct interface for a shared store. If you need a sync
// wrapper, use tokio::runtime::Handle::current().block_on(…) at the call site.
