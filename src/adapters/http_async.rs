use crate::adapters::guard::{AdapterGuardConfig, enter_adapter_guard};
use crate::adapters::http::HttpAdapterResponse;
use crate::audit::AuditSink;
use crate::engine_async::evaluate_and_audit_with_async_state;
use crate::models::HostContext;
use crate::revocation_async::AsyncTrustStateStore;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

pub async fn handle_http_json_request_with_async_state(
    raw_body: &str,
    now: DateTime<Utc>,
    sink: &dyn AuditSink,
    trust_state: &dyn AsyncTrustStateStore,
    host_context: &HostContext,
) -> HttpAdapterResponse {
    handle_http_json_request_with_async_state_and_guard_config(
        raw_body,
        now,
        sink,
        trust_state,
        &AdapterGuardConfig::default(),
        host_context,
    )
    .await
}

pub async fn handle_http_json_request_with_async_state_and_guard_config(
    raw_body: &str,
    now: DateTime<Utc>,
    sink: &dyn AuditSink,
    trust_state: &dyn AsyncTrustStateStore,
    guard_config: &AdapterGuardConfig,
    host_context: &HostContext,
) -> HttpAdapterResponse {
    let raw_request: Value = match serde_json::from_str(raw_body) {
        Ok(value) => value,
        Err(error) => {
            return HttpAdapterResponse {
                status_code: 400,
                body: json!({
                    "allowed": false,
                    "stage": "http_adapter",
                    "reason": format!("malformed JSON body: {error}")
                }),
            };
        }
    };

    let agent_id = raw_request
        .get("agent_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown-agent");
    let delegator_id = raw_request
        .get("delegator_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown-delegator");
    let _guard_lease = match enter_adapter_guard(agent_id, delegator_id, now, guard_config) {
        Ok(lease) => lease,
        Err(violation) => {
            return HttpAdapterResponse {
                status_code: 429,
                body: json!({
                    "allowed": false,
                    "stage": "adapter_guard",
                    "reason": violation.reason
                }),
            };
        }
    };

    match evaluate_and_audit_with_async_state(&raw_request, now, sink, trust_state, host_context)
        .await
    {
        Ok(decision) => {
            if decision.allowed {
                HttpAdapterResponse {
                    status_code: 200,
                    body: json!({
                        "allowed": true,
                        "stage": decision.stage,
                        "reason": decision.reason
                    }),
                }
            } else {
                HttpAdapterResponse {
                    status_code: 403,
                    body: json!({
                        "allowed": false,
                        "stage": decision.stage,
                        "reason": decision.reason
                    }),
                }
            }
        }
        Err(error) => HttpAdapterResponse {
            status_code: 500,
            body: json!({
                "allowed": false,
                "stage": "audit_sink",
                "reason": format!("failed to write audit event: {error}")
            }),
        },
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

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[55u8; 32])
    }

    fn unique_id() -> String {
        let counter = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_nanos();
        format!("{counter}_{nanos}")
    }

    fn valid_request_body() -> String {
        let unique_id = unique_id();
        let key = signing_key();
        let mut identity = AgentIdentityDocument {
            spec_version: "0.1".to_string(),
            kind: "AgentIdentityDocument".to_string(),
            agent_id: "agent:example:scheduler:v1".to_string(),
            display_name: Some("Async HTTP Scheduler".to_string()),
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
            supported_protocols: vec!["http".to_string()],
            supported_auth_methods: vec!["delegation_token".to_string()],
            capabilities: None,
            endpoints: vec![AgentEndpoint {
                protocol: "http".to_string(),
                url: "https://agents.example.ai/scheduler".to_string(),
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
            token_id: format!("dlg_http_async_{unique_id}"),
            issuer: "https://trust.example.ai".to_string(),
            agent_id: "agent:example:scheduler:v1".to_string(),
            delegator_id: "user:jake-abendroth".to_string(),
            owner_id: "org:example".to_string(),
            audience: vec!["tool:google-calendar".to_string()],
            allowed_actions: vec!["calendar.create_event".to_string()],
            resource_constraints: None,
            max_spend: None,
            max_delegation_depth: None,
            issued_at: Utc
                .with_ymd_and_hms(2026, 6, 1, 20, 10, 0)
                .single()
                .expect("valid timestamp"),
            expires_at: Utc
                .with_ymd_and_hms(2026, 6, 1, 20, 40, 0)
                .single()
                .expect("valid timestamp"),
            intent: None,
            nonce: format!("nonce-http-async-{unique_id}"),
            key_id: "key-2026-01".to_string(),
            signature_alg: TOKEN_SIGNATURE_ALG_ED25519.to_string(),
            signature: String::new(),
        };
        token.signature = sign_delegation_token(&token, &key).expect("token signing");

        let envelope = RequestEnvelope {
            spec_version: "0.1".to_string(),
            kind: "TrustRequestEnvelope".to_string(),
            request_id: Some(format!("req_http_async_{unique_id}")),
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
        serde_json::to_string(&envelope).expect("serialization should work")
    }

    #[tokio::test]
    async fn async_http_returns_200_on_allow() {
        let state = InMemoryAsyncTrustState::new();
        let path = std::env::temp_dir().join(format!(
            "delegated_http_async_allow_{}.jsonl",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        ));
        let sink = JsonlFileAuditSink::new(path.clone());
        let response = handle_http_json_request_with_async_state(
            &valid_request_body(),
            now(),
            &sink,
            &state,
            &HostContext::default(),
        )
        .await;
        assert_eq!(response.status_code, 200);
        std::fs::remove_file(path).expect("temporary audit file should be removable");
    }

    #[tokio::test]
    async fn async_http_returns_400_on_malformed_body() {
        let state = InMemoryAsyncTrustState::new();
        let sink = crate::audit::JsonlFileAuditSink::new(
            std::env::temp_dir().join("delegated_http_async_malformed.jsonl"),
        );
        let response = handle_http_json_request_with_async_state(
            "{bad json",
            now(),
            &sink,
            &state,
            &HostContext::default(),
        )
        .await;
        assert_eq!(response.status_code, 400);
    }

    #[tokio::test]
    async fn async_http_blocks_nonce_replay() {
        let state = InMemoryAsyncTrustState::new();
        let path = std::env::temp_dir().join(format!(
            "delegated_http_async_replay_{}.jsonl",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        ));
        let sink = JsonlFileAuditSink::new(path.clone());
        let body = valid_request_body();
        let first = handle_http_json_request_with_async_state(
            &body,
            now(),
            &sink,
            &state,
            &HostContext::default(),
        )
        .await;
        let second = handle_http_json_request_with_async_state(
            &body,
            now(),
            &sink,
            &state,
            &HostContext::default(),
        )
        .await;
        assert_eq!(first.status_code, 200);
        assert_eq!(second.status_code, 403);
        std::fs::remove_file(path).expect("temporary audit file should be removable");
    }
}
