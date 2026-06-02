use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::fs;
use std::path::{Path, PathBuf};
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

pub trait TrustStateStore {
    fn is_token_revoked(&self, token_id: &str) -> Result<bool, TrustStateError>;
    fn is_agent_emergency_denied(&self, agent_id: &str) -> Result<bool, TrustStateError>;
    fn consume_nonce(
        &mut self,
        nonce: &str,
        valid_until: DateTime<Utc>,
    ) -> Result<bool, TrustStateError>;
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryTrustState {
    revoked_token_ids: HashSet<String>,
    emergency_denied_agents: HashSet<String>,
    consumed_nonces: HashMap<String, DateTime<Utc>>,
    backend_available: bool,
}

impl InMemoryTrustState {
    pub fn new() -> Self {
        Self {
            revoked_token_ids: HashSet::new(),
            emergency_denied_agents: HashSet::new(),
            consumed_nonces: HashMap::new(),
            backend_available: true,
        }
    }

    pub fn revoke_token(&mut self, token_id: impl Into<String>) {
        self.revoked_token_ids.insert(token_id.into());
    }

    pub fn emergency_deny_agent(&mut self, agent_id: impl Into<String>) {
        self.emergency_denied_agents.insert(agent_id.into());
    }

    pub fn clear_nonce_history(&mut self) {
        self.consumed_nonces.clear();
    }

    pub fn set_backend_available(&mut self, available: bool) {
        self.backend_available = available;
    }

    fn purge_expired_nonces(&mut self, reference_time: DateTime<Utc>) {
        self.consumed_nonces
            .retain(|_, expires_at| *expires_at >= reference_time);
    }

    fn ensure_available(&self) -> Result<(), TrustStateError> {
        if self.backend_available {
            Ok(())
        } else {
            Err(TrustStateError::new("revocation backend unavailable"))
        }
    }
}

impl TrustStateStore for InMemoryTrustState {
    fn is_token_revoked(&self, token_id: &str) -> Result<bool, TrustStateError> {
        self.ensure_available()?;
        Ok(self.revoked_token_ids.contains(token_id))
    }

    fn is_agent_emergency_denied(&self, agent_id: &str) -> Result<bool, TrustStateError> {
        self.ensure_available()?;
        Ok(self.emergency_denied_agents.contains(agent_id))
    }

    fn consume_nonce(
        &mut self,
        nonce: &str,
        valid_until: DateTime<Utc>,
    ) -> Result<bool, TrustStateError> {
        self.ensure_available()?;
        self.purge_expired_nonces(valid_until);
        if self.consumed_nonces.contains_key(nonce) {
            return Ok(false);
        }
        self.consumed_nonces.insert(nonce.to_string(), valid_until);
        Ok(true)
    }
}

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

    pub fn revoke_token(&mut self, token_id: impl Into<String>) -> Result<(), TrustStateError> {
        self.ensure_available()?;
        let _lock = self.acquire_lock()?;
        let mut persisted = self.load_persisted()?;
        persisted.revoked_token_ids.insert(token_id.into());
        self.save_persisted(&persisted)
    }

    pub fn emergency_deny_agent(
        &mut self,
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
        let mut attempts = 0u8;
        loop {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(_) => {
                    return Ok(FileLockGuard { lock_path });
                }
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
        &mut self,
        nonce: &str,
        valid_until: DateTime<Utc>,
    ) -> Result<bool, TrustStateError> {
        self.ensure_available()?;
        let _lock = self.acquire_lock()?;
        let mut persisted = self.load_persisted()?;
        persisted
            .consumed_nonces
            .retain(|_, expires_at| *expires_at >= valid_until);
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

    fn valid_until() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0)
            .single()
            .expect("valid timestamp")
    }

    #[test]
    fn in_memory_nonce_replay_is_blocked() {
        let mut store = InMemoryTrustState::new();
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
    fn file_store_persists_revocations_and_nonce_consumption() {
        let path = std::env::temp_dir().join(format!(
            "agentauth_trust_state_{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        ));
        let mut store = FileBackedTrustState::new(path.clone());
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
}
