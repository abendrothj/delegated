use crate::audit::AuditSink;
use crate::engine::evaluate_and_audit_with_state;
use crate::models::RequestEnvelope;
use crate::revocation::{RuntimeTrustConfig, TrustStateStore, trust_state_from_runtime_config};
use crate::wire::{SHARED_CLAIMS_KIND, SharedTrustClaims};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Map, Value, json};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct McpJsonRpcResponse {
    pub jsonrpc: String,
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

pub fn handle_mcp_jsonrpc_request(
    raw_body: &str,
    now: DateTime<Utc>,
    sink: &dyn AuditSink,
) -> McpJsonRpcResponse {
    handle_mcp_jsonrpc_request_with_runtime_config(
        raw_body,
        now,
        sink,
        &RuntimeTrustConfig::default(),
    )
}

pub fn handle_mcp_jsonrpc_request_with_runtime_config(
    raw_body: &str,
    now: DateTime<Utc>,
    sink: &dyn AuditSink,
    runtime_config: &RuntimeTrustConfig,
) -> McpJsonRpcResponse {
    let mut trust_state = trust_state_from_runtime_config(runtime_config);
    handle_mcp_jsonrpc_request_with_state(raw_body, now, sink, trust_state.as_mut())
}

pub fn handle_mcp_jsonrpc_request_with_state(
    raw_body: &str,
    now: DateTime<Utc>,
    sink: &dyn AuditSink,
    trust_state: &mut dyn TrustStateStore,
) -> McpJsonRpcResponse {
    let raw_request: Value = match serde_json::from_str(raw_body) {
        Ok(value) => value,
        Err(error) => {
            return jsonrpc_error(
                None,
                -32700,
                format!("parse error: {error}"),
                Some(json!({"stage":"mcp_adapter"})),
            );
        }
    };

    let object = match raw_request.as_object() {
        Some(object) => object,
        None => {
            return jsonrpc_error(
                None,
                -32600,
                "invalid request: body must be a JSON object".to_string(),
                Some(json!({"stage":"mcp_adapter"})),
            );
        }
    };

    let id = object.get("id").cloned();
    let version = object.get("jsonrpc").and_then(Value::as_str).unwrap_or("");
    if version != "2.0" {
        return jsonrpc_error(
            id,
            -32600,
            "invalid request: jsonrpc must equal 2.0".to_string(),
            Some(json!({"stage":"mcp_adapter"})),
        );
    }

    let params = match object.get("params").and_then(Value::as_object) {
        Some(params) => params,
        None => {
            return jsonrpc_error(
                id,
                -32602,
                "invalid params: params must be an object".to_string(),
                Some(json!({"stage":"mcp_adapter"})),
            );
        }
    };
    let claims = match parse_shared_claims(params) {
        Ok(claims) => claims,
        Err(error_response) => return error_response.with_id(id),
    };
    let envelope: RequestEnvelope = claims.into();
    let raw_envelope = match serde_json::to_value(envelope) {
        Ok(value) => value,
        Err(error) => {
            return jsonrpc_error(
                id,
                -32603,
                format!("failed to encode request envelope: {error}"),
                Some(json!({"stage":"mcp_adapter"})),
            );
        }
    };

    match evaluate_and_audit_with_state(&raw_envelope, now, sink, trust_state) {
        Ok(decision) if decision.allowed => McpJsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(json!({
                "allowed": true,
                "stage": decision.stage,
                "reason": decision.reason
            })),
            error: None,
        },
        Ok(decision) => jsonrpc_error(
            id,
            -32001,
            "trust policy denied request".to_string(),
            Some(json!({
                "allowed": false,
                "stage": decision.stage,
                "reason": decision.reason
            })),
        ),
        Err(error) => jsonrpc_error(
            id,
            -32603,
            format!("adapter failed to emit audit event: {error}"),
            Some(json!({"stage":"audit_sink"})),
        ),
    }
}

fn parse_shared_claims(
    params: &Map<String, Value>,
) -> Result<SharedTrustClaims, AdapterErrorResponse> {
    let raw_claims = params.get("_trust").ok_or_else(|| {
        AdapterErrorResponse::new(
            -32602,
            "invalid params: params._trust is required".to_string(),
            Some(json!({"stage":"mcp_adapter"})),
        )
    })?;
    let claims: SharedTrustClaims =
        serde_json::from_value(raw_claims.clone()).map_err(|error| {
            AdapterErrorResponse::new(
                -32602,
                format!("invalid params: params._trust is malformed: {error}"),
                Some(json!({"stage":"mcp_adapter"})),
            )
        })?;
    if claims.kind != SHARED_CLAIMS_KIND {
        return Err(AdapterErrorResponse::new(
            -32602,
            format!("invalid params: params._trust.kind must equal {SHARED_CLAIMS_KIND}"),
            Some(json!({"stage":"mcp_adapter"})),
        ));
    }
    Ok(claims)
}

#[derive(Debug, Clone)]
struct AdapterErrorResponse {
    code: i64,
    message: String,
    data: Option<Value>,
}

impl AdapterErrorResponse {
    fn new(code: i64, message: String, data: Option<Value>) -> Self {
        Self {
            code,
            message,
            data,
        }
    }

    fn with_id(self, id: Option<Value>) -> McpJsonRpcResponse {
        jsonrpc_error(id, self.code, self.message, self.data)
    }
}

fn jsonrpc_error(
    id: Option<Value>,
    code: i64,
    message: String,
    data: Option<Value>,
) -> McpJsonRpcResponse {
    McpJsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: None,
        error: Some(json!({
            "code": code,
            "message": message,
            "data": data
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::JsonlFileAuditSink;
    use crate::crypto::{
        TOKEN_SIGNATURE_ALG_ED25519, sign_delegation_token, sign_identity_document,
    };
    use crate::models::{
        AgentEndpoint, AgentIdentityDocument, DelegationToken, PublicKeyRecord, RequestEnvelope,
        RuntimeContext, TrustProfile,
    };
    use crate::revocation::InMemoryTrustState;
    use base64ct::{Base64UrlUnpadded, Encoding};
    use chrono::TimeZone;
    use ed25519_dalek::SigningKey;
    use std::sync::atomic::{AtomicU64, Ordering};

    static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 1, 20, 20, 0)
            .single()
            .expect("valid test timestamp")
    }

    fn unique_id() -> String {
        let counter = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_nanos();
        format!("{counter}_{nanos}")
    }

    fn signed_shared_claims(nonce: &str) -> SharedTrustClaims {
        let unique_id = unique_id();
        let key = SigningKey::from_bytes(&[12u8; 32]);
        let mut identity = AgentIdentityDocument {
            spec_version: "0.1".to_string(),
            kind: "AgentIdentityDocument".to_string(),
            agent_id: "agent:example:scheduler:v1".to_string(),
            display_name: None,
            owner_id: "org:example".to_string(),
            issuer: "https://trust.example.ai".to_string(),
            identity_type: "spiffe".to_string(),
            subject: "spiffe://example.ai/agents/scheduler".to_string(),
            public_keys: vec![PublicKeyRecord {
                kid: "key-2026-01".to_string(),
                kty: "OKP".to_string(),
                crv: Some(TOKEN_SIGNATURE_ALG_ED25519.to_string()),
                x: Some(Base64UrlUnpadded::encode_string(
                    &key.verifying_key().to_bytes(),
                )),
            }],
            supported_protocols: vec!["mcp".to_string()],
            supported_auth_methods: vec!["delegation_token".to_string()],
            capabilities: None,
            endpoints: vec![AgentEndpoint {
                protocol: "mcp".to_string(),
                url: "https://agents.example.ai/scheduler/mcp".to_string(),
            }],
            attestation: None,
            created_at: Utc
                .with_ymd_and_hms(2026, 6, 1, 20, 0, 0)
                .single()
                .expect("valid timestamp"),
            expires_at: Utc
                .with_ymd_and_hms(2026, 6, 8, 20, 0, 0)
                .single()
                .expect("valid timestamp"),
            signature: String::new(),
        };
        identity.signature = sign_identity_document(&identity, &key).expect("identity signing");

        let mut token = DelegationToken {
            spec_version: "0.1".to_string(),
            kind: "DelegationToken".to_string(),
            token_id: format!("dlg_mcp_{unique_id}"),
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
            nonce: nonce.to_string(),
            key_id: "key-2026-01".to_string(),
            signature_alg: TOKEN_SIGNATURE_ALG_ED25519.to_string(),
            signature: String::new(),
        };
        token.signature = sign_delegation_token(&token, &key).expect("token signing");
        let request = RequestEnvelope {
            spec_version: "0.1".to_string(),
            kind: "TrustRequestEnvelope".to_string(),
            request_id: Some(format!("req_mcp_{unique_id}")),
            profile: TrustProfile::Developer,
            agent_id: "agent:example:scheduler:v1".to_string(),
            delegator_id: "user:jake-abendroth".to_string(),
            audience: "tool:google-calendar".to_string(),
            action: "calendar.create_event".to_string(),
            resource: None,
            runtime_context: RuntimeContext {
                requested_spend: None,
                spend_currency: None,
                delegation_depth: Some(0),
                target_email: None,
                target_calendar_id: None,
                cognitive_judge_scores_bps: Some(vec![9200, 9100]),
                cognitive_challenge_pass_bps: Some(9100),
                reputation_score_bps: Some(8200),
                risk_challenge_passed: None,
                extra_approval_granted: None,
            },
            identity_document: Some(identity),
            token,
        };
        request.into()
    }

    fn unique_nonce(prefix: &str) -> String {
        format!("{prefix}-{}", unique_id())
    }

    #[test]
    fn allows_valid_mcp_request() {
        let nonce = unique_nonce("nonce-mcp");
        let body = json!({
            "jsonrpc":"2.0",
            "id":"msg-1",
            "method":"tools.call",
            "params":{
                "_trust": signed_shared_claims(&nonce),
                "_payload":{"tool":"calendar.create_event"}
            }
        })
        .to_string();
        let sink_path = std::env::temp_dir().join(format!(
            "agentauth_mcp_{}.jsonl",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        ));
        let sink = JsonlFileAuditSink::new(sink_path.clone());
        let response = handle_mcp_jsonrpc_request(&body, now(), &sink);
        assert!(response.error.is_none());
        assert_eq!(
            response.result.as_ref().and_then(|v| v.get("allowed")),
            Some(&json!(true))
        );
        std::fs::remove_file(sink_path).expect("temporary audit file should be removable");
    }

    #[test]
    fn blocks_nonce_replay_in_mcp_stateful_path() {
        let replay_nonce = unique_nonce("nonce-mcp-replay");
        let body = json!({
            "jsonrpc":"2.0",
            "id":"msg-2",
            "method":"tools.call",
            "params":{
                "_trust": signed_shared_claims(&replay_nonce),
                "_payload":{"tool":"calendar.create_event"}
            }
        })
        .to_string();
        let sink_path = std::env::temp_dir().join(format!(
            "agentauth_mcp_replay_{}.jsonl",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        ));
        let sink = JsonlFileAuditSink::new(sink_path.clone());
        let mut state = InMemoryTrustState::new();
        let first = handle_mcp_jsonrpc_request_with_state(&body, now(), &sink, &mut state);
        let second = handle_mcp_jsonrpc_request_with_state(&body, now(), &sink, &mut state);
        assert!(first.error.is_none());
        assert!(second.error.is_some());
        assert_eq!(
            second
                .error
                .as_ref()
                .and_then(|e| e.get("data"))
                .and_then(|d| d.get("reason")),
            Some(&json!("delegation token nonce replay detected"))
        );
        std::fs::remove_file(sink_path).expect("temporary audit file should be removable");
    }
}
