use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub stage: &'static str,
    pub reason: String,
}

impl Violation {
    pub fn new(stage: &'static str, reason: impl Into<String>) -> Self {
        Self {
            stage,
            reason: reason.into(),
        }
    }
}

impl Display for Violation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.stage, self.reason)
    }
}

impl Error for Violation {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationToken {
    pub spec_version: String,
    pub kind: String,
    pub token_id: String,
    pub issuer: String,
    pub agent_id: String,
    pub delegator_id: String,
    pub owner_id: String,
    pub audience: Vec<String>,
    pub allowed_actions: Vec<String>,
    pub resource_constraints: Option<ResourceConstraints>,
    pub max_spend: Option<MaxSpend>,
    pub max_delegation_depth: Option<u16>,
    pub approval_policy: Option<serde_json::Value>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub intent: Option<String>,
    pub nonce: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub spec_version: String,
    pub kind: String,
    pub request_id: Option<String>,
    pub agent_id: String,
    pub delegator_id: String,
    pub audience: String,
    pub action: String,
    pub resource: Option<String>,
    #[serde(default)]
    pub runtime_context: RuntimeContext,
    pub identity_document: Option<AgentIdentityDocument>,
    #[serde(rename = "delegation_token")]
    pub token: DelegationToken,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceConstraints {
    pub calendar_ids: Option<Vec<String>>,
    pub email_domain_allowlist: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RuntimeContext {
    pub requested_spend: Option<i64>,
    pub spend_currency: Option<String>,
    pub delegation_depth: Option<u16>,
    pub target_email: Option<String>,
    pub target_calendar_id: Option<String>,
    pub cognitive_judge_scores_bps: Option<Vec<u16>>,
    pub cognitive_challenge_pass_bps: Option<u16>,
    pub reputation_score_bps: Option<u16>,
    pub risk_challenge_passed: Option<bool>,
    pub extra_approval_granted: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIdentityDocument {
    pub spec_version: String,
    pub kind: String,
    pub agent_id: String,
    pub display_name: Option<String>,
    pub owner_id: String,
    pub issuer: String,
    pub identity_type: String,
    pub subject: String,
    pub public_keys: Vec<PublicKeyRecord>,
    pub supported_protocols: Vec<String>,
    pub supported_auth_methods: Vec<String>,
    pub capabilities: Option<Vec<String>>,
    pub endpoints: Vec<AgentEndpoint>,
    pub attestation: Option<AttestationRecord>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyRecord {
    pub kid: String,
    pub kty: String,
    pub crv: Option<String>,
    pub x: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentEndpoint {
    pub protocol: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationRecord {
    #[serde(rename = "type")]
    pub type_name: String,
    pub issuer: String,
    pub evidence_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaxSpend {
    pub amount: i64,
    pub currency: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Decision {
    pub allowed: bool,
    pub stage: String,
    pub reason: String,
}

impl Decision {
    pub fn allow(stage: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            allowed: true,
            stage: stage.into(),
            reason: reason.into(),
        }
    }

    pub fn deny(stage: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            stage: stage.into(),
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditEvent {
    pub occurred_at: DateTime<Utc>,
    pub allowed: bool,
    pub stage: String,
    pub reason: String,
    pub request_id: Option<String>,
    pub agent_id: Option<String>,
    pub delegator_id: Option<String>,
    pub audience: Option<String>,
    pub action: Option<String>,
    pub token_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyCheck {
    pub name: String,
    pub passed: bool,
    pub reason: String,
}
