use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(not(test))]
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustStateError {
    message: String,
}

impl TrustStateError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Display for TrustStateError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for TrustStateError {}

/// Read-only trust checks used during request evaluation.
///
/// All methods take `&self` — implementations must use interior mutability
/// (e.g. `Mutex`, `DashMap`, or a database transaction) so that they can be
/// shared via `Arc<dyn TrustStateStore>` or called behind a `&dyn` reference.
pub trait TrustStateStore {
    fn is_token_revoked(&self, token_id: &str) -> Result<bool, TrustStateError>;
    fn is_agent_emergency_denied(&self, agent_id: &str) -> Result<bool, TrustStateError>;
    /// Atomically record that a nonce has been consumed, returning `true` if it
    /// was fresh or `false` if it was already seen (replay).
    fn consume_nonce(
        &self,
        nonce: &str,
        valid_until: DateTime<Utc>,
    ) -> Result<bool, TrustStateError>;
}

/// Administrative operations for managing revocation and deny-list state.
///
/// Extends [`TrustStateStore`]. Default implementations are provided for
/// `revoke_tokens` (loops over `revoke_token`) and `flush_expired_nonces`
/// (no-op for stores that handle expiry externally, e.g. Redis TTL).
pub trait TrustStateAdmin: TrustStateStore {
    fn revoke_token(&self, token_id: &str) -> Result<(), TrustStateError>;
    fn emergency_deny_agent(&self, agent_id: &str) -> Result<(), TrustStateError>;
    /// Clear all entries from the emergency deny list. Returns the count removed.
    fn clear_emergency_deny_list(&self) -> Result<u64, TrustStateError>;

    /// Revoke multiple tokens atomically where possible. Returns the count revoked.
    fn revoke_tokens(&self, token_ids: &[&str]) -> Result<u64, TrustStateError> {
        let mut count = 0u64;
        for id in token_ids {
            self.revoke_token(id)?;
            count += 1;
        }
        Ok(count)
    }

    /// Flush consumed nonces that have expired as of `reference_time`.
    /// Returns the count removed. The default is a no-op for backends that
    /// handle expiry externally (e.g. Redis `EXAT`).
    fn flush_expired_nonces(&self, _reference_time: DateTime<Utc>) -> Result<u64, TrustStateError> {
        Ok(0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustStateBackend {
    DurableDefault,
    DurablePath(PathBuf),
    InMemory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeTrustConfig {
    pub backend: TrustStateBackend,
}

impl RuntimeTrustConfig {
    pub fn durable_default() -> Self {
        Self {
            backend: TrustStateBackend::DurableDefault,
        }
    }

    pub fn durable_path(path: impl Into<PathBuf>) -> Self {
        Self {
            backend: TrustStateBackend::DurablePath(path.into()),
        }
    }

    pub fn in_memory() -> Self {
        Self {
            backend: TrustStateBackend::InMemory,
        }
    }
}

impl Default for RuntimeTrustConfig {
    fn default() -> Self {
        Self::in_memory()
    }
}

pub const SHARED_BACKEND_REQUIRED_REASON: &str =
    "shared backend required in production mode; use async state with RedisTrustStateStore";

fn is_truthy_env(value: Option<std::ffi::OsString>) -> bool {
    matches!(
        value
            .as_deref()
            .and_then(|v| v.to_str())
            .map(|v| v.to_ascii_lowercase())
            .as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
}

fn is_production_env(value: Option<std::ffi::OsString>) -> bool {
    matches!(
        value
            .as_deref()
            .and_then(|v| v.to_str())
            .map(|v| v.to_ascii_lowercase())
            .as_deref(),
        Some("prod" | "production")
    )
}

pub fn require_shared_backend_in_production() -> bool {
    is_truthy_env(std::env::var_os("DELEGATED_REQUIRE_SHARED_BACKEND"))
        || is_production_env(std::env::var_os("DELEGATED_ENV"))
}

pub fn default_trust_state_path() -> PathBuf {
    if let Some(override_path) = std::env::var_os("DELEGATED_TRUST_STATE_PATH") {
        return PathBuf::from(override_path);
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join(".delegated")
            .join("trust-state.json");
    }
    PathBuf::from(".delegated").join("trust-state.json")
}

#[cfg(test)]
fn default_in_memory_runtime_store() -> Arc<dyn TrustStateStore> {
    Arc::new(InMemoryTrustState::new())
}

#[cfg(not(test))]
fn default_in_memory_runtime_store() -> Arc<dyn TrustStateStore> {
    static STATE: OnceLock<Arc<InMemoryTrustState>> = OnceLock::new();
    STATE
        .get_or_init(|| Arc::new(InMemoryTrustState::new()))
        .clone()
}

pub fn trust_state_from_runtime_config(config: &RuntimeTrustConfig) -> Arc<dyn TrustStateStore> {
    match &config.backend {
        TrustStateBackend::DurableDefault => {
            Arc::new(FileBackedTrustState::new(default_trust_state_path()))
        }
        TrustStateBackend::DurablePath(path) => Arc::new(FileBackedTrustState::new(path.clone())),
        TrustStateBackend::InMemory => default_in_memory_runtime_store(),
    }
}

#[cfg(test)]
mod production_mode_tests {
    use super::*;

    #[test]
    fn truthy_env_parser_accepts_common_values() {
        assert!(is_truthy_env(Some("1".into())));
        assert!(is_truthy_env(Some("true".into())));
        assert!(is_truthy_env(Some("YES".into())));
        assert!(!is_truthy_env(Some("0".into())));
        assert!(!is_truthy_env(None));
    }

    #[test]
    fn production_env_parser_accepts_expected_values() {
        assert!(is_production_env(Some("production".into())));
        assert!(is_production_env(Some("PROD".into())));
        assert!(!is_production_env(Some("dev".into())));
        assert!(!is_production_env(None));
    }
}

// ─── InMemoryTrustState ──────────────────────────────────────────────────────

#[derive(Debug)]
struct InMemoryTrustInner {
    revoked_token_ids: HashSet<String>,
    emergency_denied_agents: HashSet<String>,
    consumed_nonces: HashMap<String, DateTime<Utc>>,
}

/// In-memory trust state using interior mutability.
///
/// Suitable for tests and single-process deployments. For multi-process or
/// distributed production use, implement [`TrustStateStore`] against a shared
/// store (Redis, PostgreSQL, etc.).
#[derive(Debug)]
pub struct InMemoryTrustState {
    inner: Mutex<InMemoryTrustInner>,
    backend_available: AtomicBool,
}

impl Default for InMemoryTrustState {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryTrustState {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(InMemoryTrustInner {
                revoked_token_ids: HashSet::new(),
                emergency_denied_agents: HashSet::new(),
                consumed_nonces: HashMap::new(),
            }),
            backend_available: AtomicBool::new(true),
        }
    }

    pub fn set_backend_available(&self, available: bool) {
        self.backend_available.store(available, Ordering::SeqCst);
    }

    fn ensure_available(&self) -> Result<(), TrustStateError> {
        if self.backend_available.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(TrustStateError::new("revocation backend unavailable"))
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, InMemoryTrustInner>, TrustStateError> {
        self.inner
            .lock()
            .map_err(|_| TrustStateError::new("trust state mutex poisoned"))
    }
}

impl TrustStateStore for InMemoryTrustState {
    fn is_token_revoked(&self, token_id: &str) -> Result<bool, TrustStateError> {
        self.ensure_available()?;
        let inner = self.lock()?;
        Ok(inner.revoked_token_ids.contains(token_id))
    }

    fn is_agent_emergency_denied(&self, agent_id: &str) -> Result<bool, TrustStateError> {
        self.ensure_available()?;
        let inner = self.lock()?;
        Ok(inner.emergency_denied_agents.contains(agent_id))
    }

    fn consume_nonce(
        &self,
        nonce: &str,
        valid_until: DateTime<Utc>,
    ) -> Result<bool, TrustStateError> {
        self.ensure_available()?;
        let mut inner = self.lock()?;
        // Prune against a stable reference that never exceeds the current token's validity.
        // This avoids evicting earlier-but-still-valid consumed nonces when a later-expiry
        // token arrives, while keeping replay behavior deterministic for older test fixtures.
        let prune_before = std::cmp::min(Utc::now(), valid_until);
        inner
            .consumed_nonces
            .retain(|_, expires_at| *expires_at >= prune_before);
        if inner.consumed_nonces.contains_key(nonce) {
            return Ok(false);
        }
        inner.consumed_nonces.insert(nonce.to_string(), valid_until);
        Ok(true)
    }
}

impl TrustStateAdmin for InMemoryTrustState {
    fn revoke_token(&self, token_id: &str) -> Result<(), TrustStateError> {
        self.ensure_available()?;
        let mut inner = self.lock()?;
        inner.revoked_token_ids.insert(token_id.to_string());
        Ok(())
    }

    fn emergency_deny_agent(&self, agent_id: &str) -> Result<(), TrustStateError> {
        self.ensure_available()?;
        let mut inner = self.lock()?;
        inner.emergency_denied_agents.insert(agent_id.to_string());
        Ok(())
    }

    fn clear_emergency_deny_list(&self) -> Result<u64, TrustStateError> {
        self.ensure_available()?;
        let mut inner = self.lock()?;
        let count = inner.emergency_denied_agents.len() as u64;
        inner.emergency_denied_agents.clear();
        Ok(count)
    }

    fn flush_expired_nonces(&self, reference_time: DateTime<Utc>) -> Result<u64, TrustStateError> {
        self.ensure_available()?;
        let mut inner = self.lock()?;
        let before = inner.consumed_nonces.len();
        inner
            .consumed_nonces
            .retain(|_, expires_at| *expires_at >= reference_time);
        Ok((before - inner.consumed_nonces.len()) as u64)
    }
}

// ─── FileBackedTrustState ─────────────────────────────────────────────────────

/// File-backed trust state for CLI and single-process deployments.
///
/// **Limitations**: state is stored in a single JSON file and protected by a process-local
/// advisory lock file. It is not safe for use across multiple concurrent processes or on
/// network filesystems. For multi-process or high-throughput deployments, implement
/// `TrustStateStore` against a shared database or distributed cache instead.
///
/// The lock uses a spin-wait with a 200ms total timeout; sustained concurrent writers
/// will contend and may fail. Revocation reads acquire the lock on every request —
/// this does not scale beyond low-volume CLI or dev use.
#[derive(Debug, Clone)]
pub struct FileBackedTrustState {
    path: PathBuf,
    backend_available: bool,
}

impl FileBackedTrustState {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            backend_available: true,
        }
    }

    pub fn set_backend_available(&mut self, available: bool) {
        self.backend_available = available;
    }

    pub fn revoke_token_local(&self, token_id: impl Into<String>) -> Result<(), TrustStateError> {
        self.ensure_available()?;
        let _lock = self.acquire_lock()?;
        let mut persisted = self.load_persisted()?;
        persisted.revoked_token_ids.insert(token_id.into());
        self.save_persisted(&persisted)
    }

    pub fn emergency_deny_agent_local(
        &self,
        agent_id: impl Into<String>,
    ) -> Result<(), TrustStateError> {
        self.ensure_available()?;
        let _lock = self.acquire_lock()?;
        let mut persisted = self.load_persisted()?;
        persisted.emergency_denied_agents.insert(agent_id.into());
        self.save_persisted(&persisted)
    }

    fn ensure_available(&self) -> Result<(), TrustStateError> {
        if self.backend_available {
            Ok(())
        } else {
            Err(TrustStateError::new("revocation backend unavailable"))
        }
    }

    fn lock_path(&self) -> PathBuf {
        self.path.with_extension("lock")
    }

    fn acquire_lock(&self) -> Result<FileLockGuard, TrustStateError> {
        let lock_path = self.lock_path();
        if let Some(parent) = lock_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|error| {
                TrustStateError::new(format!(
                    "failed creating trust-state lock directory: {error}"
                ))
            })?;
        }
        let mut attempts = 0u8;
        loop {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(_) => return Ok(FileLockGuard { lock_path }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    attempts += 1;
                    if attempts > 20 {
                        return Err(TrustStateError::new(
                            "timed out acquiring trust-state file lock",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => {
                    return Err(TrustStateError::new(format!(
                        "failed acquiring trust-state file lock: {error}"
                    )));
                }
            }
        }
    }

    fn load_persisted(&self) -> Result<PersistedTrustState, TrustStateError> {
        if !self.path.exists() {
            return Ok(PersistedTrustState::default());
        }
        let raw = fs::read_to_string(&self.path).map_err(|error| {
            TrustStateError::new(format!("failed reading trust-state file: {error}"))
        })?;
        serde_json::from_str(&raw).map_err(|error| {
            TrustStateError::new(format!("failed parsing trust-state file: {error}"))
        })
    }

    fn save_persisted(&self, persisted: &PersistedTrustState) -> Result<(), TrustStateError> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new(""));
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|error| {
                TrustStateError::new(format!("failed creating trust-state directory: {error}"))
            })?;
        }
        let encoded = serde_json::to_string_pretty(persisted).map_err(|error| {
            TrustStateError::new(format!("failed encoding trust-state: {error}"))
        })?;
        fs::write(&self.path, encoded).map_err(|error| {
            TrustStateError::new(format!("failed writing trust-state file: {error}"))
        })
    }
}

impl TrustStateStore for FileBackedTrustState {
    fn is_token_revoked(&self, token_id: &str) -> Result<bool, TrustStateError> {
        self.ensure_available()?;
        let _lock = self.acquire_lock()?;
        let persisted = self.load_persisted()?;
        Ok(persisted.revoked_token_ids.contains(token_id))
    }

    fn is_agent_emergency_denied(&self, agent_id: &str) -> Result<bool, TrustStateError> {
        self.ensure_available()?;
        let _lock = self.acquire_lock()?;
        let persisted = self.load_persisted()?;
        Ok(persisted.emergency_denied_agents.contains(agent_id))
    }

    fn consume_nonce(
        &self,
        nonce: &str,
        valid_until: DateTime<Utc>,
    ) -> Result<bool, TrustStateError> {
        self.ensure_available()?;
        let _lock = self.acquire_lock()?;
        let mut persisted = self.load_persisted()?;
        let prune_before = std::cmp::min(Utc::now(), valid_until);
        persisted
            .consumed_nonces
            .retain(|_, expires_at| *expires_at >= prune_before);
        if persisted.consumed_nonces.contains_key(nonce) {
            return Ok(false);
        }
        persisted
            .consumed_nonces
            .insert(nonce.to_string(), valid_until);
        self.save_persisted(&persisted)?;
        Ok(true)
    }
}

impl TrustStateAdmin for FileBackedTrustState {
    fn revoke_token(&self, token_id: &str) -> Result<(), TrustStateError> {
        self.revoke_token_local(token_id.to_string())
    }

    fn emergency_deny_agent(&self, agent_id: &str) -> Result<(), TrustStateError> {
        self.emergency_deny_agent_local(agent_id.to_string())
    }

    fn clear_emergency_deny_list(&self) -> Result<u64, TrustStateError> {
        self.ensure_available()?;
        let _lock = self.acquire_lock()?;
        let mut persisted = self.load_persisted()?;
        let count = persisted.emergency_denied_agents.len() as u64;
        persisted.emergency_denied_agents.clear();
        self.save_persisted(&persisted)?;
        Ok(count)
    }

    fn flush_expired_nonces(&self, reference_time: DateTime<Utc>) -> Result<u64, TrustStateError> {
        self.ensure_available()?;
        let _lock = self.acquire_lock()?;
        let mut persisted = self.load_persisted()?;
        let before = persisted.consumed_nonces.len();
        persisted
            .consumed_nonces
            .retain(|_, expires_at| *expires_at >= reference_time);
        let removed = before - persisted.consumed_nonces.len();
        if removed > 0 {
            self.save_persisted(&persisted)?;
        }
        Ok(removed as u64)
    }
}

#[derive(Debug)]
struct FileLockGuard {
    lock_path: PathBuf,
}

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PersistedTrustState {
    revoked_token_ids: HashSet<String>,
    emergency_denied_agents: HashSet<String>,
    consumed_nonces: HashMap<String, DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use proptest::prelude::*;

    fn valid_until() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0)
            .single()
            .expect("valid timestamp")
    }

    #[test]
    fn in_memory_nonce_replay_is_blocked() {
        let store = InMemoryTrustState::new();
        assert!(
            store
                .consume_nonce("nonce-1", valid_until())
                .expect("first consume should succeed")
        );
        assert!(
            !store
                .consume_nonce("nonce-1", valid_until())
                .expect("second consume should be blocked")
        );
    }

    #[test]
    fn in_memory_nonce_replay_is_blocked_with_mixed_expiries() {
        let store = InMemoryTrustState::new();
        let now = Utc::now();
        let first_expiry = now + chrono::Duration::minutes(5);
        let second_expiry = now + chrono::Duration::minutes(30);

        assert!(
            store
                .consume_nonce("nonce-short", first_expiry)
                .expect("first consume should succeed")
        );
        assert!(
            store
                .consume_nonce("nonce-long", second_expiry)
                .expect("different nonce should succeed")
        );
        assert!(
            !store
                .consume_nonce("nonce-short", first_expiry)
                .expect("replay of first nonce should be blocked")
        );
    }

    #[test]
    fn in_memory_bulk_revoke_and_clear() {
        let store = InMemoryTrustState::new();
        let ids = ["dlg_a", "dlg_b", "dlg_c"];
        let count = store
            .revoke_tokens(&ids)
            .expect("bulk revoke should succeed");
        assert_eq!(count, 3);
        for id in &ids {
            assert!(store.is_token_revoked(id).expect("query should succeed"));
        }

        store
            .emergency_deny_agent("agent:bad")
            .expect("deny should succeed");
        assert_eq!(
            store
                .clear_emergency_deny_list()
                .expect("clear should succeed"),
            1
        );
        assert!(
            !store
                .is_agent_emergency_denied("agent:bad")
                .expect("query should succeed")
        );
    }

    #[test]
    fn in_memory_flush_expired_nonces() {
        let store = InMemoryTrustState::new();
        let past = Utc
            .with_ymd_and_hms(2020, 1, 1, 0, 0, 0)
            .single()
            .expect("valid ts");
        // Consume a nonce that is already expired. Do not consume anything with a
        // future expiry afterward — the retain inside consume_nonce would clear it.
        store
            .consume_nonce("old", past)
            .expect("consume should succeed");
        let reference = Utc
            .with_ymd_and_hms(2025, 1, 1, 0, 0, 0)
            .single()
            .expect("valid ts");
        let flushed = store
            .flush_expired_nonces(reference)
            .expect("flush should succeed");
        assert_eq!(flushed, 1);
    }

    #[test]
    fn file_store_persists_revocations_and_nonce_consumption() {
        let path = std::env::temp_dir().join(format!(
            "delegated_trust_state_{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        ));
        let store = FileBackedTrustState::new(path.clone());
        store
            .revoke_token("dlg_abc")
            .expect("revoke operation should persist");
        assert!(
            store
                .is_token_revoked("dlg_abc")
                .expect("revocation query should succeed")
        );
        assert!(
            store
                .consume_nonce("nonce-abc", valid_until())
                .expect("nonce consume should succeed")
        );
        assert!(
            !store
                .consume_nonce("nonce-abc", valid_until())
                .expect("nonce replay should be blocked")
        );
        std::fs::remove_file(&path).expect("state file should be removable");
    }

    #[test]
    fn file_store_clear_emergency_deny_list() {
        let path = std::env::temp_dir().join(format!(
            "delegated_trust_state_clear_{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        ));
        let store = FileBackedTrustState::new(path.clone());
        store
            .emergency_deny_agent("agent:bad")
            .expect("deny should persist");
        assert_eq!(
            store
                .clear_emergency_deny_list()
                .expect("clear should succeed"),
            1
        );
        assert!(
            !store
                .is_agent_emergency_denied("agent:bad")
                .expect("query should succeed")
        );
        std::fs::remove_file(&path).expect("state file should be removable");
    }

    #[test]
    fn file_store_nonce_replay_is_blocked_with_mixed_expiries() {
        let path = std::env::temp_dir().join(format!(
            "delegated_trust_state_mixed_replay_{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        ));
        let store = FileBackedTrustState::new(path.clone());
        let now = Utc::now();
        let first_expiry = now + chrono::Duration::minutes(5);
        let second_expiry = now + chrono::Duration::minutes(30);

        assert!(
            store
                .consume_nonce("nonce-short", first_expiry)
                .expect("first consume should succeed")
        );
        assert!(
            store
                .consume_nonce("nonce-long", second_expiry)
                .expect("different nonce should succeed")
        );
        assert!(
            !store
                .consume_nonce("nonce-short", first_expiry)
                .expect("replay of first nonce should be blocked")
        );
        std::fs::remove_file(&path).expect("state file should be removable");
    }

    proptest! {
        #[test]
        fn in_memory_nonce_replay_is_blocked_for_random_nonce_sets(
            nonces in proptest::collection::hash_set("[a-z0-9]{1,24}", 1..32),
            expiry_offsets in proptest::collection::vec(1u16..120, 1..32),
        ) {
            let store = InMemoryTrustState::new();
            let now = Utc::now();
            for (nonce, offset_minutes) in nonces.iter().zip(expiry_offsets.iter().cycle()) {
                let expiry = now + chrono::Duration::minutes(i64::from(*offset_minutes));
                prop_assert!(store
                    .consume_nonce(nonce, expiry)
                    .expect("first consume should succeed"));
            }
            for (nonce, offset_minutes) in nonces.iter().zip(expiry_offsets.iter().cycle()) {
                let expiry = now + chrono::Duration::minutes(i64::from(*offset_minutes));
                prop_assert!(!store
                    .consume_nonce(nonce, expiry)
                    .expect("replay consume should be blocked"));
            }
        }
    }
}
