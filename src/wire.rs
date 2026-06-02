use crate::models::{
    AgentIdentityDocument, DelegationToken, RequestEnvelope, RuntimeContext, TrustProfile,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROTOCOL_A2A: &str = "a2a";
pub const PROTOCOL_MCP: &str = "mcp";
pub const SHARED_CLAIMS_KIND: &str = "SharedTrustClaims";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedTrustClaims {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2aTrustEnvelope {
    pub protocol: String,
    pub protocol_version: String,
    pub trust_claims: SharedTrustClaims,
    pub a2a_payload: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpTrustEnvelope {
    pub protocol: String,
    pub protocol_version: String,
    pub trust_claims: SharedTrustClaims,
    pub mcp_payload: Value,
}

impl From<RequestEnvelope> for SharedTrustClaims {
    fn from(request: RequestEnvelope) -> Self {
        Self {
            spec_version: request.spec_version,
            kind: SHARED_CLAIMS_KIND.to_string(),
            request_id: request.request_id,
            profile: request.profile,
            agent_id: request.agent_id,
            delegator_id: request.delegator_id,
            audience: request.audience,
            action: request.action,
            resource: request.resource,
            runtime_context: request.runtime_context,
            identity_document: request.identity_document,
            token: request.token,
        }
    }
}

impl From<SharedTrustClaims> for RequestEnvelope {
    fn from(claims: SharedTrustClaims) -> Self {
        Self {
            spec_version: claims.spec_version,
            kind: "TrustRequestEnvelope".to_string(),
            request_id: claims.request_id,
            profile: claims.profile,
            agent_id: claims.agent_id,
            delegator_id: claims.delegator_id,
            audience: claims.audience,
            action: claims.action,
            resource: claims.resource,
            runtime_context: claims.runtime_context,
            identity_document: claims.identity_document,
            token: claims.token,
        }
    }
}

pub fn wrap_a2a_request(
    request: RequestEnvelope,
    protocol_version: impl Into<String>,
    a2a_payload: Value,
) -> A2aTrustEnvelope {
    A2aTrustEnvelope {
        protocol: PROTOCOL_A2A.to_string(),
        protocol_version: protocol_version.into(),
        trust_claims: request.into(),
        a2a_payload,
    }
}

pub fn wrap_mcp_request(
    request: RequestEnvelope,
    protocol_version: impl Into<String>,
    mcp_payload: Value,
) -> McpTrustEnvelope {
    McpTrustEnvelope {
        protocol: PROTOCOL_MCP.to_string(),
        protocol_version: protocol_version.into(),
        trust_claims: request.into(),
        mcp_payload,
    }
}

pub fn unwrap_a2a_claims(envelope: A2aTrustEnvelope) -> RequestEnvelope {
    envelope.trust_claims.into()
}

pub fn unwrap_mcp_claims(envelope: McpTrustEnvelope) -> RequestEnvelope {
    envelope.trust_claims.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::DelegationToken;
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    fn sample_request() -> RequestEnvelope {
        RequestEnvelope {
            spec_version: "0.1".to_string(),
            kind: "TrustRequestEnvelope".to_string(),
            request_id: Some("req_wire_123".to_string()),
            profile: TrustProfile::Developer,
            agent_id: "agent:example:scheduler:v1".to_string(),
            delegator_id: "user:jake-abendroth".to_string(),
            audience: "tool:google-calendar".to_string(),
            action: "calendar.create_event".to_string(),
            resource: None,
            runtime_context: RuntimeContext::default(),
            identity_document: None,
            token: DelegationToken {
                spec_version: "0.1".to_string(),
                kind: "DelegationToken".to_string(),
                token_id: "dlg_wire_123".to_string(),
                issuer: "https://trust.example.ai".to_string(),
                agent_id: "agent:example:scheduler:v1".to_string(),
                delegator_id: "user:jake-abendroth".to_string(),
                owner_id: "org:example".to_string(),
                audience: vec!["tool:google-calendar".to_string()],
                allowed_actions: vec!["calendar.create_event".to_string()],
                resource_constraints: None,
                max_spend: None,
                max_delegation_depth: Some(0),
                approval_policy: None,
                issued_at: Utc
                    .with_ymd_and_hms(2026, 6, 1, 20, 10, 0)
                    .single()
                    .expect("valid timestamp"),
                expires_at: Utc
                    .with_ymd_and_hms(2026, 6, 1, 20, 40, 0)
                    .single()
                    .expect("valid timestamp"),
                intent: None,
                nonce: "nonce-wire".to_string(),
                key_id: "key-2026-01".to_string(),
                signature_alg: "Ed25519".to_string(),
                signature: "base64url-signature".to_string(),
            },
        }
    }

    #[test]
    fn wraps_and_unwraps_a2a_claims_with_shared_payload() {
        let request = sample_request();
        let envelope = wrap_a2a_request(request.clone(), "1.0", json!({"task":"schedule"}));
        assert_eq!(envelope.protocol, PROTOCOL_A2A);
        assert_eq!(envelope.trust_claims.kind, SHARED_CLAIMS_KIND);
        assert_eq!(envelope.a2a_payload["task"], json!("schedule"));

        let unwrapped = unwrap_a2a_claims(envelope);
        assert_eq!(unwrapped.agent_id, request.agent_id);
        assert_eq!(unwrapped.token.token_id, request.token.token_id);
    }

    #[test]
    fn wraps_and_unwraps_mcp_claims_with_shared_payload() {
        let request = sample_request();
        let envelope = wrap_mcp_request(request.clone(), "2026-06-01", json!({"tool":"calendar"}));
        assert_eq!(envelope.protocol, PROTOCOL_MCP);
        assert_eq!(envelope.trust_claims.kind, SHARED_CLAIMS_KIND);
        assert_eq!(envelope.mcp_payload["tool"], json!("calendar"));

        let unwrapped = unwrap_mcp_claims(envelope);
        assert_eq!(unwrapped.delegator_id, request.delegator_id);
        assert_eq!(unwrapped.token.issuer, request.token.issuer);
    }
}
