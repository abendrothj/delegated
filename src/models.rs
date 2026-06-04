use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

/// Context supplied by the host application from trusted external sources.
/// These fields must never be populated from the incoming request envelope — they represent
/// infrastructure-verified state (reputation services, cognitive oracles, human approvals).
#[derive(Debug, Clone)]
pub struct HostContext {
    /// Delegation chain depth tracked by the infrastructure, not reported by the agent.
    pub delegation_depth: Option<u16>,
    /// Scores (0–10000 bps) from independent external cognitive judges.
    /// When `None`, cognitive verification is not configured and the gate is skipped.
    pub cognitive_judge_scores_bps: Option<Vec<u16>>,
    /// Overall challenge pass rate from an external challenge service (0–10000 bps).
    pub cognitive_challenge_pass_bps: Option<u16>,
    /// Agent reputation score from an external reputation service (0–10000 bps).
    pub reputation_score_bps: Option<u16>,
    /// Whether the agent passed an additional risk challenge from an external risk service.
    pub risk_challenge_passed: Option<bool>,
    /// Whether a human operator explicitly granted extra approval for this request.
    pub extra_approval_granted: Option<bool>,
    /// Permitted clock skew in seconds for token/document lifetime checks. Default: 30.
    pub clock_leeway_secs: u64,
}

impl Default for HostContext {
    fn default() -> Self {
        Self {
            delegation_depth: None,
            cognitive_judge_scores_bps: None,
            cognitive_challenge_pass_bps: None,
            reputation_score_bps: None,
            risk_challenge_passed: None,
            extra_approval_granted: None,
            clock_leeway_secs: 30,
        }
    }
}

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
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub intent: Option<String>,
    pub nonce: String,
    pub key_id: String,
    pub signature_alg: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub spec_version: String,
    pub kind: String,
    pub request_id: Option<String>,
    #[serde(default)]
    pub profile: TrustProfile,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TrustProfile {
    #[default]
    Developer,
    Oidc,
    Spiffe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceConstraints {
    pub calendar_ids: Option<Vec<String>>,
    pub email_domain_allowlist: Option<Vec<String>>,
    /// Host-defined additional constraints; keys are constraint names, values are allowlists.
    #[serde(flatten)]
    pub extra: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RuntimeContext {
    pub requested_spend: Option<i64>,
    pub spend_currency: Option<String>,
    pub target_email: Option<String>,
    pub target_calendar_id: Option<String>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyCheck {
    pub name: String,
    pub passed: bool,
    pub reason: String,
}
