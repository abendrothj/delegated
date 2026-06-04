use crate::adapters::guard::{AdapterGuardConfig, enter_adapter_guard};
use crate::adapters::mcp::McpJsonRpcResponse;
use crate::audit::AuditSink;
use crate::engine_async::evaluate_and_audit_with_async_state;
use crate::models::{HostContext, RequestEnvelope};
use crate::revocation_async::AsyncTrustStateStore;
use crate::wire::{SHARED_CLAIMS_KIND, SharedTrustClaims};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

pub async fn handle_mcp_jsonrpc_request_with_async_state(
    raw_body: &str,
    now: DateTime<Utc>,
    sink: &dyn AuditSink,
    trust_state: &dyn AsyncTrustStateStore,
    host_context: &HostContext,
) -> McpJsonRpcResponse {
    handle_mcp_jsonrpc_request_with_async_state_and_guard_config(
        raw_body,
        now,
        sink,
        trust_state,
        &AdapterGuardConfig::default(),
        host_context,
    )
    .await
}

pub async fn handle_mcp_jsonrpc_request_with_async_state_and_guard_config(
    raw_body: &str,
    now: DateTime<Utc>,
    sink: &dyn AuditSink,
    trust_state: &dyn AsyncTrustStateStore,
    guard_config: &AdapterGuardConfig,
    host_context: &HostContext,
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
        Err((code, msg, data)) => return jsonrpc_error(id, code, msg, data),
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

    match evaluate_and_audit_with_async_state(&raw_envelope, now, sink, trust_state, host_context)
        .await
    {
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
) -> Result<SharedTrustClaims, (i64, String, Option<Value>)> {
    let raw_claims = params.get("_trust").ok_or_else(|| {
        (
            -32602i64,
            "invalid params: params._trust is required".to_string(),
            Some(json!({"stage":"mcp_adapter"})),
        )
    })?;
    let claims: SharedTrustClaims =
        serde_json::from_value(raw_claims.clone()).map_err(|error| {
            (
                -32602i64,
                format!("invalid params: params._trust is malformed: {error}"),
                Some(json!({"stage":"mcp_adapter"})),
            )
        })?;
    if claims.kind != SHARED_CLAIMS_KIND {
        return Err((
            -32602,
            format!("invalid params: params._trust.kind must equal {SHARED_CLAIMS_KIND}"),
            Some(json!({"stage":"mcp_adapter"})),
        ));
    }
    Ok(claims)
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
    use crate::revocation_async::InMemoryAsyncTrustState;
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

    fn signed_claims(nonce: &str) -> SharedTrustClaims {
        let unique_id = unique_id();
        let key = SigningKey::from_bytes(&[66u8; 32]);
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
            token_id: format!("dlg_mcp_async_{unique_id}"),
            issuer: "https://trust.example.ai".to_string(),
            agent_id: "agent:example:scheduler:v1".to_string(),
            delegator_id: "user:jake-abendroth".to_string(),
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
        let envelope = RequestEnvelope {
            spec_version: "0.1".to_string(),
            kind: "TrustRequestEnvelope".to_string(),
            request_id: Some(format!("req_mcp_async_{unique_id}")),
            profile: TrustProfile::Developer,
            agent_id: "agent:example:scheduler:v1".to_string(),
            delegator_id: "user:jake-abendroth".to_string(),
            audience: "tool:google-calendar".to_string(),
            action: "calendar.create_event".to_string(),
            resource: None,
            runtime_context: RuntimeContext::default(),
            identity_document: Some(identity),
            token,
        };
        envelope.into()
    }

    #[tokio::test]
    async fn async_mcp_allows_valid_request() {
        let nonce = format!(
            "nonce-mcp-async-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("epoch")
                .as_nanos()
        );
        let body = json!({
            "jsonrpc": "2.0",
            "id": "msg-async-1",
            "method": "tools.call",
            "params": {
                "_trust": signed_claims(&nonce),
                "_payload": {"tool": "calendar.create_event"}
            }
        })
        .to_string();
        let state = InMemoryAsyncTrustState::new();
        let path = std::env::temp_dir().join(format!(
            "delegated_mcp_async_{}.jsonl",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("epoch")
                .as_nanos()
        ));
        let sink = JsonlFileAuditSink::new(path.clone());
        let response = handle_mcp_jsonrpc_request_with_async_state(
            &body,
            now(),
            &sink,
            &state,
            &HostContext::default(),
        )
        .await;
        assert!(response.error.is_none(), "unexpected error: {:?}", response.error);
        std::fs::remove_file(path).expect("temporary audit file should be removable");
    }

    #[tokio::test]
    async fn async_mcp_blocks_nonce_replay() {
        let nonce = format!(
            "nonce-mcp-async-replay-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("epoch")
                .as_nanos()
        );
        let body = json!({
            "jsonrpc": "2.0",
            "id": "msg-async-replay",
            "method": "tools.call",
            "params": {
                "_trust": signed_claims(&nonce),
                "_payload": {}
            }
        })
        .to_string();
        let state = InMemoryAsyncTrustState::new();
        let path = std::env::temp_dir().join(format!(
            "delegated_mcp_async_replay_{}.jsonl",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("epoch")
                .as_nanos()
        ));
        let sink = JsonlFileAuditSink::new(path.clone());
        let first = handle_mcp_jsonrpc_request_with_async_state(
            &body,
            now(),
            &sink,
            &state,
            &HostContext::default(),
        )
        .await;
        let second = handle_mcp_jsonrpc_request_with_async_state(
            &body,
            now(),
            &sink,
            &state,
            &HostContext::default(),
        )
        .await;
        assert!(first.error.is_none());
        assert!(second.error.is_some());
        std::fs::remove_file(path).expect("temporary audit file should be removable");
    }
}
