use crate::audit::AuditSink;
use crate::engine::evaluate_and_audit;
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

    match evaluate_and_audit(&raw_request, now, sink) {
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
    use crate::models::AuditEvent;
    use chrono::TimeZone;
    use std::io;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 1, 20, 20, 0)
            .single()
            .expect("valid test timestamp")
    }

    fn valid_request_body() -> String {
        json!({
            "spec_version": "0.1",
            "kind": "TrustRequestEnvelope",
            "request_id": "req_http_123",
            "agent_id": "agent:example:scheduler:v1",
            "delegator_id": "user:jake-abendroth",
            "audience": "tool:google-calendar",
            "action": "calendar.create_event",
            "runtime_context": {
                "cognitive_judge_scores_bps": [9300, 9100],
                "cognitive_challenge_pass_bps": 9200,
                "reputation_score_bps": 8200
            },
            "delegation_token": {
                "spec_version": "0.1",
                "kind": "DelegationToken",
                "token_id": "dlg_http_01",
                "issuer": "https://trust.example.ai",
                "agent_id": "agent:example:scheduler:v1",
                "delegator_id": "user:jake-abendroth",
                "owner_id": "org:example",
                "audience": ["tool:google-calendar"],
                "allowed_actions": ["calendar.create_event"],
                "issued_at": "2026-06-01T20:10:00Z",
                "expires_at": "2026-06-01T20:40:00Z",
                "nonce": "random-nonce",
                "key_id": "key-2026-01",
                "signature_alg": "Ed25519",
                "signature": "base64url-signature"
            }
        })
        .to_string()
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

    struct FailingSink;

    impl AuditSink for FailingSink {
        fn write_event(&self, _event: &AuditEvent) -> io::Result<()> {
            Err(io::Error::other("sink unavailable"))
        }
    }
}
