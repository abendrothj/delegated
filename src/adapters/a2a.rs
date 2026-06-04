use crate::adapters::guard::{AdapterGuardConfig, enter_adapter_guard};
use crate::audit::AuditSink;
use crate::engine::evaluate_and_audit_with_state;
use crate::models::{HostContext, RequestEnvelope};
use crate::revocation::{RuntimeTrustConfig, TrustStateStore, trust_state_from_runtime_config};
use crate::wire::{SHARED_CLAIMS_KIND, SharedTrustClaims};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2aProtocolRequest {
    pub message_id: String,
    pub protocol_version: String,
    pub message_type: String,
    pub trust_claims: SharedTrustClaims,
    pub payload: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2aProtocolResponse {
    pub message_id: String,
    pub status: String,
    pub result: Option<Value>,
    pub error: Option<Value>,
}

pub fn handle_a2a_request(
    raw_body: &str,
    now: DateTime<Utc>,
    sink: &dyn AuditSink,
) -> A2aProtocolResponse {
    handle_a2a_request_with_runtime_config(raw_body, now, sink, &RuntimeTrustConfig::default())
}

pub fn handle_a2a_request_with_runtime_config(
    raw_body: &str,
    now: DateTime<Utc>,
    sink: &dyn AuditSink,
    runtime_config: &RuntimeTrustConfig,
) -> A2aProtocolResponse {
    let mut trust_state = trust_state_from_runtime_config(runtime_config);
    handle_a2a_request_with_state(
        raw_body,
        now,
        sink,
        trust_state.as_mut(),
        &HostContext::default(),
    )
}

pub fn handle_a2a_request_with_state(
    raw_body: &str,
    now: DateTime<Utc>,
    sink: &dyn AuditSink,
    trust_state: &mut dyn TrustStateStore,
    host_context: &HostContext,
) -> A2aProtocolResponse {
    handle_a2a_request_with_state_and_guard_config(
        raw_body,
        now,
        sink,
        trust_state,
        &AdapterGuardConfig::default(),
        host_context,
    )
}

pub fn handle_a2a_request_with_state_and_guard_config(
    raw_body: &str,
    now: DateTime<Utc>,
    sink: &dyn AuditSink,
    trust_state: &mut dyn TrustStateStore,
    guard_config: &AdapterGuardConfig,
    host_context: &HostContext,
) -> A2aProtocolResponse {
    let request: A2aProtocolRequest = match serde_json::from_str(raw_body) {
        Ok(value) => value,
        Err(error) => {
            return A2aProtocolResponse {
                message_id: "unknown".to_string(),
                status: "error".to_string(),
                result: None,
                error: Some(
                    json!({"stage":"a2a_adapter","reason":format!("malformed A2A request: {error}")}),
                ),
            };
        }
    };
    if request.trust_claims.kind != SHARED_CLAIMS_KIND {
        return A2aProtocolResponse {
            message_id: request.message_id,
            status: "error".to_string(),
            result: None,
            error: Some(
                json!({"stage":"a2a_adapter","reason":format!("trust_claims.kind must equal {SHARED_CLAIMS_KIND}")}),
            ),
        };
    }
    let _guard_lease = match enter_adapter_guard(
        &request.trust_claims.agent_id,
        &request.trust_claims.delegator_id,
        now,
        guard_config,
    ) {
        Ok(lease) => lease,
        Err(violation) => {
            return A2aProtocolResponse {
                message_id: request.message_id,
                status: "denied".to_string(),
                result: None,
                error: Some(json!({
                    "stage":"adapter_guard",
                    "reason": violation.reason
                })),
            };
        }
    };
    let envelope: RequestEnvelope = request.trust_claims.into();
    let raw_envelope = match serde_json::to_value(envelope) {
        Ok(value) => value,
        Err(error) => {
            return A2aProtocolResponse {
                message_id: request.message_id,
                status: "error".to_string(),
                result: None,
                error: Some(
                    json!({"stage":"a2a_adapter","reason":format!("failed to encode request envelope: {error}")}),
                ),
            };
        }
    };

    match evaluate_and_audit_with_state(&raw_envelope, now, sink, trust_state, host_context) {
        Ok(decision) if decision.allowed => A2aProtocolResponse {
            message_id: request.message_id,
            status: "ok".to_string(),
            result: Some(json!({
                "allowed": true,
                "stage": decision.stage,
                "reason": decision.reason
            })),
            error: None,
        },
        Ok(decision) => A2aProtocolResponse {
            message_id: request.message_id,
            status: "denied".to_string(),
            result: None,
            error: Some(json!({
                "stage": decision.stage,
                "reason": decision.reason
            })),
        },
        Err(error) => A2aProtocolResponse {
            message_id: request.message_id,
            status: "error".to_string(),
            result: None,
            error: Some(
                json!({"stage":"audit_sink","reason":format!("failed to write audit event: {error}")}),
            ),
        },
    }
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

    fn claims_for_actor(nonce: &str, delegator_id: &str) -> SharedTrustClaims {
        let unique_id = unique_id();
        let key = SigningKey::from_bytes(&[13u8; 32]);
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
            supported_protocols: vec!["a2a".to_string()],
            supported_auth_methods: vec!["delegation_token".to_string()],
            capabilities: None,
            endpoints: vec![AgentEndpoint {
                protocol: "a2a".to_string(),
                url: "https://agents.example.ai/scheduler/a2a".to_string(),
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
            token_id: format!("dlg_a2a_{unique_id}"),
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
            request_id: Some(format!("req_a2a_{unique_id}")),
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

    fn claims(nonce: &str) -> SharedTrustClaims {
        claims_for_actor(nonce, "user:jake-abendroth")
    }

    fn unique_nonce(prefix: &str) -> String {
        format!("{prefix}-{}", unique_id())
    }

    #[test]
    fn allows_valid_a2a_message() {
        let nonce = unique_nonce("nonce-a2a");
        let req = A2aProtocolRequest {
            message_id: "msg-a2a-1".to_string(),
            protocol_version: "2026-06-01".to_string(),
            message_type: "task.request".to_string(),
            trust_claims: claims(&nonce),
            payload: json!({"task":"schedule"}),
        };
        let sink_path = std::env::temp_dir().join(format!(
            "delegated_a2a_{}.jsonl",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        ));
        let sink = JsonlFileAuditSink::new(sink_path.clone());
        let response = handle_a2a_request(
            &serde_json::to_string(&req).expect("serialization should work"),
            now(),
            &sink,
        );
        assert_eq!(response.status, "ok");
        std::fs::remove_file(sink_path).expect("temporary audit file should be removable");
    }

    #[test]
    fn denies_replay_in_stateful_a2a_path() {
        let replay_nonce = unique_nonce("nonce-a2a-replay");
        let req = A2aProtocolRequest {
            message_id: "msg-a2a-2".to_string(),
            protocol_version: "2026-06-01".to_string(),
            message_type: "task.request".to_string(),
            trust_claims: claims(&replay_nonce),
            payload: json!({"task":"schedule"}),
        };
        let sink_path = std::env::temp_dir().join(format!(
            "delegated_a2a_replay_{}.jsonl",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        ));
        let sink = JsonlFileAuditSink::new(sink_path.clone());
        let mut state = InMemoryTrustState::new();
        let serialized = serde_json::to_string(&req).expect("serialization should work");
        let first = handle_a2a_request_with_state(
            &serialized,
            now(),
            &sink,
            &mut state,
            &HostContext::default(),
        );
        let second = handle_a2a_request_with_state(
            &serialized,
            now(),
            &sink,
            &mut state,
            &HostContext::default(),
        );
        assert_eq!(first.status, "ok");
        assert_eq!(second.status, "denied");
        assert_eq!(
            second.error.as_ref().and_then(|e| e.get("reason")),
            Some(&json!("delegation token nonce replay detected"))
        );
        std::fs::remove_file(sink_path).expect("temporary audit file should be removable");
    }

    #[test]
    fn returns_denied_rate_limit_error_when_throttled() {
        let delegator = format!(
            "user:a2a-rate-limit:{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        );
        let config = AdapterGuardConfig {
            max_requests_per_minute: 1,
            max_inflight_per_tuple: 4,
        };
        let first_req = A2aProtocolRequest {
            message_id: "msg-a2a-rate-1".to_string(),
            protocol_version: "2026-06-01".to_string(),
            message_type: "task.request".to_string(),
            trust_claims: claims_for_actor(&unique_nonce("nonce-a2a-rate-one"), &delegator),
            payload: json!({"task":"schedule"}),
        };
        let second_req = A2aProtocolRequest {
            message_id: "msg-a2a-rate-2".to_string(),
            protocol_version: "2026-06-01".to_string(),
            message_type: "task.request".to_string(),
            trust_claims: claims_for_actor(&unique_nonce("nonce-a2a-rate-two"), &delegator),
            payload: json!({"task":"schedule"}),
        };
        let sink_path = std::env::temp_dir().join(format!(
            "delegated_a2a_rate_{}.jsonl",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        ));
        let sink = JsonlFileAuditSink::new(sink_path.clone());
        let mut state = InMemoryTrustState::new();
        let first = handle_a2a_request_with_state_and_guard_config(
            &serde_json::to_string(&first_req).expect("serialization should work"),
            now(),
            &sink,
            &mut state,
            &config,
            &HostContext::default(),
        );
        let second = handle_a2a_request_with_state_and_guard_config(
            &serde_json::to_string(&second_req).expect("serialization should work"),
            now(),
            &sink,
            &mut state,
            &config,
            &HostContext::default(),
        );
        assert_eq!(first.status, "ok");
        assert_eq!(second.status, "denied");
        assert_eq!(
            second.error.as_ref().and_then(|e| e.get("reason")),
            Some(&json!("rate limit exceeded for agent/delegator tuple"))
        );
        std::fs::remove_file(sink_path).expect("temporary audit file should be removable");
    }
}
