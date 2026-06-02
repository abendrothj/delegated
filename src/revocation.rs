use std::collections::HashSet;

#[derive(Debug, Clone, Default)]
pub struct InMemoryTrustState {
    revoked_token_ids: HashSet<String>,
    emergency_denied_agents: HashSet<String>,
    consumed_nonces: HashSet<String>,
    backend_available: bool,
}

impl InMemoryTrustState {
    pub fn new() -> Self {
        Self {
            revoked_token_ids: HashSet::new(),
            emergency_denied_agents: HashSet::new(),
            consumed_nonces: HashSet::new(),
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

    pub fn is_token_revoked(&self, token_id: &str) -> Result<bool, &'static str> {
        if !self.backend_available {
            return Err("revocation backend unavailable");
        }
        Ok(self.revoked_token_ids.contains(token_id))
    }

    pub fn is_agent_emergency_denied(&self, agent_id: &str) -> Result<bool, &'static str> {
        if !self.backend_available {
            return Err("revocation backend unavailable");
        }
        Ok(self.emergency_denied_agents.contains(agent_id))
    }

    pub fn consume_nonce(&mut self, nonce: &str) -> Result<bool, &'static str> {
        if !self.backend_available {
            return Err("revocation backend unavailable");
        }
        Ok(self.consumed_nonces.insert(nonce.to_string()))
    }
}
