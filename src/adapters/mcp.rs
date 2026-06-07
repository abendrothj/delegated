use crate::adapters::guard::{AdapterGuardConfig, enter_adapter_guard};
use crate::audit::AuditSink;
use crate::engine::evaluate_and_audit_with_state;
use crate::models::{HostContext, RequestEnvelope};
use crate::revocation::{
    RuntimeTrustConfig, SHARED_BACKEND_REQUIRED_REASON, TrustStateStore,
    require_shared_backend_in_production, trust_state_from_runtime_config,
};
use crate::wire::{SHARED_CLAIMS_KIND, SharedTrustClaims};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Map, Value, json};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct McpJsonRpcResponse {
    pub jsonrpc: String,
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

/// The outcome of the MCP adapter's trust evaluation.
///
/// Callers in a sidecar or proxy context must handle both variants:
/// - `Respond` — return this JSON-RPC response directly to the client.
/// - `PassThrough` — the method is not trust-gated; forward the original
///   request to the upstream MCP server unchanged.
#[derive(Debug)]
pub enum McpAdapterDecision {
    Respond(McpJsonRpcResponse),
    PassThrough,
}

impl McpAdapterDecision {
    pub fn is_pass_through(&self) -> bool {
        matches!(self, Self::PassThrough)
    }

    pub fn response(&self) -> Option<&McpJsonRpcResponse> {
        match self {
            Self::Respond(r) => Some(r),
            Self::PassThrough => None,
        }
    }

    pub fn into_response(self) -> Option<McpJsonRpcResponse> {
        match self {
            Self::Respond(r) => Some(r),
            Self::PassThrough => None,
        }
    }
}

/// Returns true for the trust-gated tool-call method.
///
/// Accepts both `tools/call` (MCP 2025 spec) and `tools.call` (signet
/// dot-notation wire format) so sidecar deployments work with both naming
/// conventions without requiring a migration.
fn is_tool_call(method: &str) -> bool {
    method == "tools/call" || method == "tools.call"
}

pub fn handle_mcp_jsonrpc_request(
    raw_body: &str,
    now: DateTime<Utc>,
    sink: &dyn AuditSink,
) -> McpAdapterDecision {
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
) -> McpAdapterDecision {
    if require_shared_backend_in_production() {
        return jsonrpc_error(
            None,
            -32603,
            SHARED_BACKEND_REQUIRED_REASON.to_string(),
            Some(json!({"stage":"runtime_config"})),
        );
    }
    let trust_state = trust_state_from_runtime_config(runtime_config);
    handle_mcp_jsonrpc_request_with_state(
        raw_body,
        now,
        sink,
        trust_state.as_ref(),
        &HostContext::default(),
    )
}

pub fn handle_mcp_jsonrpc_request_with_state(
    raw_body: &str,
    now: DateTime<Utc>,
    sink: &dyn AuditSink,
    trust_state: &dyn TrustStateStore,
    host_context: &HostContext,
) -> McpAdapterDecision {
    handle_mcp_jsonrpc_request_with_state_and_guard_config(
        raw_body,
        now,
        sink,
        trust_state,
        &AdapterGuardConfig::default(),
        host_context,
    )
}

pub fn handle_mcp_jsonrpc_request_with_state_and_guard_config(
    raw_body: &str,
    now: DateTime<Utc>,
    sink: &dyn AuditSink,
    trust_state: &dyn TrustStateStore,
    guard_config: &AdapterGuardConfig,
    host_context: &HostContext,
) -> McpAdapterDecision {
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

    let method = match object.get("method").and_then(Value::as_str) {
        Some(method) => method,
        None => {
            return jsonrpc_error(
                id,
                -32600,
                "invalid request: method must be a string".to_string(),
                Some(json!({"stage":"mcp_adapter"})),
            );
        }
    };

    // Non-tool-call methods (tools/list, prompts/get, resources/read, etc.) are
    // not trust-gated. Signal pass-through so the caller can forward them to the
    // upstream MCP server unchanged.
    if !is_tool_call(method) {
        return McpAdapterDecision::PassThrough;
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
        Err(error_response) => return McpAdapterDecision::Respond(error_response.with_id(id)),
    };
    let _guard_lease =
        match enter_adapter_guard(&claims.agent_id, &claims.delegator_id, now, guard_config) {
            Ok(lease) => lease,
            Err(violation) => {
                return jsonrpc_error(
                    id,
                    -32029,
                    "adapter throttled request".to_string(),
                    Some(json!({"stage":"adapter_guard","reason":violation.reason})),
                );
            }
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

    match evaluate_and_audit_with_state(&raw_envelope, now, sink, trust_state, host_context) {
        Ok(decision) if decision.allowed => McpAdapterDecision::Respond(McpJsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(json!({
                "allowed": true,
                "stage": decision.stage,
                "reason": decision.reason
            })),
            error: None,
        }),
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
        match jsonrpc_error(id, self.code, self.message, self.data) {
            McpAdapterDecision::Respond(r) => r,
            McpAdapterDecision::PassThrough => unreachable!("jsonrpc_error always returns Respond"),
        }
    }
}

fn jsonrpc_error(
    id: Option<Value>,
    code: i64,
    message: String,
    data: Option<Value>,
) -> McpAdapterDecision {
    McpAdapterDecision::Respond(McpJsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: None,
        error: Some(json!({
            "code": code,
            "message": message,
            "data": data
        })),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::guard::AdapterGuardConfig;
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

    fn signed_shared_claims_for_actor(nonce: &str, delegator_id: &str) -> SharedTrustClaims {
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
            delegator_id: delegator_id.to_string(),
            owner_id: "org:example".to_string(),
            audience: vec!["tool:google-calendar".to_string()],
            allowed_actions: vec!["calendar.create_event".to_string()],
            resource_constraints: None,
            max_spend: None,
            max_delegation_depth: Some(0),
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
            delegator_id: delegator_id.to_string(),
            audience: "tool:google-calendar".to_string(),
            action: "calendar.create_event".to_string(),
            resource: None,
            runtime_context: RuntimeContext::default(),
            identity_document: Some(identity),
            token,
        };
        request.into()
    }

    fn signed_shared_claims(nonce: &str) -> SharedTrustClaims {
        signed_shared_claims_for_actor(nonce, "user:jake-abendroth")
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
            "delegated_mcp_{}.jsonl",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        ));
        let sink = JsonlFileAuditSink::new(sink_path.clone());
        let McpAdapterDecision::Respond(response) = handle_mcp_jsonrpc_request(&body, now(), &sink)
        else {
            panic!("expected Respond for tools.call");
        };
        assert!(response.error.is_none());
        assert_eq!(
            response.result.as_ref().and_then(|v| v.get("allowed")),
            Some(&json!(true))
        );
        std::fs::remove_file(sink_path).expect("temporary audit file should be removable");
    }

    #[test]
    fn allows_valid_mcp_request_with_slash_method() {
        let nonce = unique_nonce("nonce-mcp-slash");
        let body = json!({
            "jsonrpc":"2.0",
            "id":"msg-slash-1",
            "method":"tools/call",
            "params":{
                "_trust": signed_shared_claims(&nonce),
                "_payload":{"tool":"calendar.create_event"}
            }
        })
        .to_string();
        let sink_path = std::env::temp_dir().join(format!(
            "delegated_mcp_slash_{}.jsonl",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        ));
        let sink = JsonlFileAuditSink::new(sink_path.clone());
        let McpAdapterDecision::Respond(response) = handle_mcp_jsonrpc_request(&body, now(), &sink)
        else {
            panic!("expected Respond for tools/call");
        };
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
            "delegated_mcp_replay_{}.jsonl",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        ));
        let sink = JsonlFileAuditSink::new(sink_path.clone());
        let state = InMemoryTrustState::new();
        let first = handle_mcp_jsonrpc_request_with_state(
            &body,
            now(),
            &sink,
            &state,
            &HostContext::default(),
        );
        let second = handle_mcp_jsonrpc_request_with_state(
            &body,
            now(),
            &sink,
            &state,
            &HostContext::default(),
        );
        let McpAdapterDecision::Respond(first_response) = first else {
            panic!("expected Respond");
        };
        let McpAdapterDecision::Respond(second_response) = second else {
            panic!("expected Respond");
        };
        assert!(first_response.error.is_none());
        assert!(second_response.error.is_some());
        assert_eq!(
            second_response
                .error
                .as_ref()
                .and_then(|e| e.get("data"))
                .and_then(|d| d.get("reason")),
            Some(&json!("delegation token nonce replay detected"))
        );
        std::fs::remove_file(sink_path).expect("temporary audit file should be removable");
    }

    #[test]
    fn returns_jsonrpc_rate_limit_error_when_throttled() {
        let delegator = format!(
            "user:mcp-rate-limit:{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        );
        let config = AdapterGuardConfig {
            max_requests_per_minute: 1,
            max_inflight_per_tuple: 4,
        };
        let first_nonce = unique_nonce("nonce-mcp-rate-one");
        let second_nonce = unique_nonce("nonce-mcp-rate-two");
        let first_body = json!({
            "jsonrpc":"2.0",
            "id":"msg-rate-1",
            "method":"tools.call",
            "params":{
                "_trust": signed_shared_claims_for_actor(&first_nonce, &delegator),
                "_payload":{"tool":"calendar.create_event"}
            }
        })
        .to_string();
        let second_body = json!({
            "jsonrpc":"2.0",
            "id":"msg-rate-2",
            "method":"tools.call",
            "params":{
                "_trust": signed_shared_claims_for_actor(&second_nonce, &delegator),
                "_payload":{"tool":"calendar.create_event"}
            }
        })
        .to_string();
        let sink_path = std::env::temp_dir().join(format!(
            "delegated_mcp_rate_{}.jsonl",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        ));
        let sink = JsonlFileAuditSink::new(sink_path.clone());
        let state = InMemoryTrustState::new();
        let first = handle_mcp_jsonrpc_request_with_state_and_guard_config(
            &first_body,
            now(),
            &sink,
            &state,
            &config,
            &HostContext::default(),
        );
        let second = handle_mcp_jsonrpc_request_with_state_and_guard_config(
            &second_body,
            now(),
            &sink,
            &state,
            &config,
            &HostContext::default(),
        );
        let McpAdapterDecision::Respond(first_response) = first else {
            panic!("expected Respond");
        };
        let McpAdapterDecision::Respond(second_response) = second else {
            panic!("expected Respond");
        };
        assert!(first_response.error.is_none());
        assert_eq!(
            second_response
                .error
                .as_ref()
                .and_then(|e| e.get("code"))
                .and_then(|c| c.as_i64()),
            Some(-32029)
        );
        assert_eq!(
            second_response
                .error
                .as_ref()
                .and_then(|e| e.get("data"))
                .and_then(|d| d.get("reason")),
            Some(&json!("rate limit exceeded for agent/delegator tuple"))
        );
        std::fs::remove_file(sink_path).expect("temporary audit file should be removable");
    }

    #[test]
    fn passes_through_non_tool_call_method() {
        let nonce = unique_nonce("nonce-mcp-passthrough");
        let sink_path = std::env::temp_dir().join(format!(
            "delegated_mcp_passthrough_{}.jsonl",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        ));
        let sink = JsonlFileAuditSink::new(sink_path.clone());

        for method in &["tools/list", "prompts/get", "resources/read", "prompts/list"] {
            let body = json!({
                "jsonrpc":"2.0",
                "id":"msg-passthrough-1",
                "method": method,
                "params":{
                    "_trust": signed_shared_claims(&nonce)
                }
            })
            .to_string();
            assert!(
                matches!(
                    handle_mcp_jsonrpc_request(&body, now(), &sink),
                    McpAdapterDecision::PassThrough
                ),
                "expected PassThrough for method {method}"
            );
        }

        let _ = std::fs::remove_file(sink_path);
    }
}
