use crate::audit::AuditSink;
use crate::engine::evaluate_and_audit_with_state;
use crate::revocation::InMemoryTrustState;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HttpAdapterResponse {
    pub status_code: u16,
    pub body: Value,
}

pub fn handle_http_json_request(
    raw_body: &str,
    now: DateTime<Utc>,
    sink: &dyn AuditSink,
) -> HttpAdapterResponse {
    let mut trust_state = InMemoryTrustState::new();
    handle_http_json_request_with_state(raw_body, now, sink, &mut trust_state)
}

pub fn handle_http_json_request_with_state(
    raw_body: &str,
    now: DateTime<Utc>,
    sink: &dyn AuditSink,
    trust_state: &mut InMemoryTrustState,
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

    match evaluate_and_audit_with_state(&raw_request, now, sink, trust_state) {
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
    use crate::audit::{AuditSink, JsonlFileAuditSink};
    use crate::crypto::{
        TOKEN_SIGNATURE_ALG_ED25519, sign_delegation_token, sign_identity_document,
    };
    use crate::models::{
        AgentEndpoint, AgentIdentityDocument, AuditEvent, DelegationToken, PublicKeyRecord,
        RequestEnvelope, RuntimeContext,
    };
    use base64ct::{Base64UrlUnpadded, Encoding};
    use chrono::TimeZone;
    use ed25519_dalek::SigningKey;
    use std::io;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 1, 20, 20, 0)
            .single()
            .expect("valid test timestamp")
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn valid_request_body() -> String {
        let key = signing_key();
        let mut identity_document = AgentIdentityDocument {
            spec_version: "0.1".to_string(),
            kind: "AgentIdentityDocument".to_string(),
            agent_id: "agent:example:scheduler:v1".to_string(),
            display_name: Some("example Scheduler Agent".to_string()),
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
        identity_document.signature =
            sign_identity_document(&identity_document, &key).expect("identity signing should work");

        let mut token = DelegationToken {
            spec_version: "0.1".to_string(),
            kind: "DelegationToken".to_string(),
            token_id: "dlg_http_01".to_string(),
            issuer: "https://trust.example.ai".to_string(),
            agent_id: "agent:example:scheduler:v1".to_string(),
            delegator_id: "user:jake-abendroth".to_string(),
            owner_id: "org:example".to_string(),
            audience: vec!["tool:google-calendar".to_string()],
            allowed_actions: vec!["calendar.create_event".to_string()],
            resource_constraints: None,
            max_spend: None,
            max_delegation_depth: None,
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
            nonce: "random-nonce".to_string(),
            key_id: "key-2026-01".to_string(),
            signature_alg: TOKEN_SIGNATURE_ALG_ED25519.to_string(),
            signature: String::new(),
        };
        token.signature = sign_delegation_token(&token, &key).expect("token signing should work");

        let request = RequestEnvelope {
            spec_version: "0.1".to_string(),
            kind: "TrustRequestEnvelope".to_string(),
            request_id: Some("req_http_123".to_string()),
            agent_id: "agent:example:scheduler:v1".to_string(),
            delegator_id: "user:jake-abendroth".to_string(),
            audience: "tool:google-calendar".to_string(),
            action: "calendar.create_event".to_string(),
            resource: None,
            runtime_context: RuntimeContext {
                requested_spend: None,
                spend_currency: None,
                delegation_depth: None,
                target_email: None,
                target_calendar_id: None,
                cognitive_judge_scores_bps: Some(vec![9300, 9100]),
                cognitive_challenge_pass_bps: Some(9200),
                reputation_score_bps: Some(8200),
                risk_challenge_passed: None,
                extra_approval_granted: None,
            },
            identity_document: Some(identity_document),
            token,
        };

        serde_json::to_string(&request).expect("request serialization should work")
    }

    #[test]
    fn returns_200_on_allow() {
        let path = std::env::temp_dir().join(format!(
            "agentauth_http_allow_{}.jsonl",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        ));
        let sink = JsonlFileAuditSink::new(path.clone());
        let response = handle_http_json_request(&valid_request_body(), now(), &sink);
        assert_eq!(response.status_code, 200);
        assert_eq!(response.body["allowed"], json!(true));
        std::fs::remove_file(path).expect("temporary audit file should be removable");
    }

    #[test]
    fn returns_403_on_policy_deny() {
        let path = std::env::temp_dir().join(format!(
            "agentauth_http_deny_{}.jsonl",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        ));
        let sink = JsonlFileAuditSink::new(path.clone());
        let mut request: Value =
            serde_json::from_str(&valid_request_body()).expect("test request should parse");
        request["action"] = json!("calendar.delete_event");

        let response = handle_http_json_request(&request.to_string(), now(), &sink);
        assert_eq!(response.status_code, 403);
        assert_eq!(response.body["allowed"], json!(false));
        std::fs::remove_file(path).expect("temporary audit file should be removable");
    }

    #[test]
    fn returns_400_on_malformed_json() {
        let sink = FailingSink;
        let response = handle_http_json_request("{invalid", now(), &sink);
        assert_eq!(response.status_code, 400);
        assert_eq!(response.body["stage"], json!("http_adapter"));
    }

    #[test]
    fn returns_500_when_audit_sink_fails() {
        let sink = FailingSink;
        let response = handle_http_json_request(&valid_request_body(), now(), &sink);
        assert_eq!(response.status_code, 500);
        assert_eq!(response.body["stage"], json!("audit_sink"));
    }

    #[test]
    fn denies_nonce_replay_with_shared_state() {
        let path = std::env::temp_dir().join(format!(
            "agentauth_http_replay_{}.jsonl",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        ));
        let sink = JsonlFileAuditSink::new(path.clone());
        let mut trust_state = InMemoryTrustState::new();
        let body = valid_request_body();

        let first = handle_http_json_request_with_state(&body, now(), &sink, &mut trust_state);
        let second = handle_http_json_request_with_state(&body, now(), &sink, &mut trust_state);

        assert_eq!(first.status_code, 200);
        assert_eq!(second.status_code, 403);
        assert_eq!(
            second.body["reason"],
            json!("delegation token nonce replay detected")
        );
        std::fs::remove_file(path).expect("temporary audit file should be removable");
    }

    struct FailingSink;

    impl AuditSink for FailingSink {
        fn write_event(&self, _event: &AuditEvent) -> io::Result<()> {
            Err(io::Error::other("sink unavailable"))
        }
    }
}
