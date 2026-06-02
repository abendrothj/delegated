use crate::models::{AuditEvent, Decision, RequestEnvelope, Violation};
use crate::stages::{
    authorize_action, normalize_request, validate_token_binding, validate_token_lifetime,
};
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;

pub fn evaluate_request(raw_request: &Value, now: DateTime<Utc>) -> (Decision, AuditEvent) {
    let result = normalize_request(raw_request)
        .and_then(|envelope| validate_token_lifetime(envelope, now))
        .and_then(validate_token_binding)
        .and_then(authorize_action);

    match result {
        Ok(envelope) => {
            let decision = Decision::allow("request authorized");
            let event = from_envelope(envelope, &decision, now);
            (decision, event)
        }
        Err(violation) => {
            let decision = Decision::deny(violation.stage, violation.reason.clone());
            let event = from_raw(raw_request, &violation, now);
            (decision, event)
        }
    }
}

pub fn append_audit_event(path: impl AsRef<Path>, event: &AuditEvent) -> io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let line = serde_json::to_string(event).map_err(io::Error::other)?;
    writeln!(file, "{line}")
}

fn from_envelope(envelope: RequestEnvelope, decision: &Decision, now: DateTime<Utc>) -> AuditEvent {
    AuditEvent {
        occurred_at: now,
        allowed: decision.allowed,
        stage: decision.stage.clone(),
        reason: decision.reason.clone(),
        request_id: envelope.request_id,
        agent_id: Some(envelope.agent_id),
        delegator_id: Some(envelope.delegator_id),
        audience: Some(envelope.audience),
        action: Some(envelope.action),
        token_id: Some(envelope.token.token_id),
    }
}

fn from_raw(raw_request: &Value, violation: &Violation, now: DateTime<Utc>) -> AuditEvent {
    let request_id = extract_string(raw_request, &["request_id"]);
    let agent_id = extract_string(raw_request, &["agent_id"]);
    let delegator_id = extract_string(raw_request, &["delegator_id"]);
    let audience = extract_string(raw_request, &["audience"]);
    let action = extract_string(raw_request, &["action"]);
    let token_id = extract_string(raw_request, &["delegation_token", "token_id"]);

    AuditEvent {
        occurred_at: now,
        allowed: false,
        stage: violation.stage.to_string(),
        reason: violation.reason.clone(),
        request_id,
        agent_id,
        delegator_id,
        audience,
        action,
        token_id,
    }
}

fn extract_string(root: &Value, path: &[&str]) -> Option<String> {
    let mut cursor = root;
    for key in path {
        cursor = cursor.get(*key)?;
    }
    let value = cursor.as_str()?.trim();
    if value.is_empty() {
        return None;
    }
    Some(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 1, 20, 20, 0)
            .single()
            .expect("valid test timestamp")
    }

    fn valid_request() -> Value {
        json!({
            "spec_version": "0.1",
            "kind": "TrustRequestEnvelope",
            "request_id": "req_123",
            "agent_id": "agent:example:scheduler:v1",
            "delegator_id": "user:jake-abendroth",
            "audience": "tool:google-calendar",
            "action": "calendar.create_event",
            "delegation_token": {
                "spec_version": "0.1",
                "kind": "DelegationToken",
                "token_id": "dlg_01J0EXAMPLE",
                "issuer": "https://trust.example.ai",
                "agent_id": "agent:example:scheduler:v1",
                "delegator_id": "user:jake-abendroth",
                "owner_id": "org:example",
                "audience": ["tool:google-calendar", "tool:gmail"],
                "allowed_actions": [
                    "calendar.create_event",
                    "calendar.read_availability",
                    "gmail.send_message"
                ],
                "issued_at": "2026-06-01T20:10:00Z",
                "expires_at": "2026-06-01T20:40:00Z",
                "intent": "schedule_demo_and_send_confirmation",
                "nonce": "random-nonce",
                "signature": "base64url-signature"
            }
        })
    }

    #[test]
    fn allows_valid_request() {
        let (decision, event) = evaluate_request(&valid_request(), now());
        assert!(decision.allowed);
        assert_eq!(decision.stage, "authorize_action");
        assert_eq!(event.allowed, true);
        assert_eq!(event.token_id.as_deref(), Some("dlg_01J0EXAMPLE"));
    }

    #[test]
    fn denies_when_action_not_allowed() {
        let mut request = valid_request();
        request["action"] = Value::String("calendar.delete_event".to_string());

        let (decision, event) = evaluate_request(&request, now());
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "authorize_action");
        assert_eq!(event.allowed, false);
    }

    #[test]
    fn denies_when_token_expired() {
        let mut request = valid_request();
        request["delegation_token"]["expires_at"] =
            Value::String("2026-06-01T20:15:00Z".to_string());

        let (decision, _event) = evaluate_request(&request, now());
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "validate_token_lifetime");
    }

    #[test]
    fn denies_when_binding_mismatch() {
        let mut request = valid_request();
        request["delegation_token"]["agent_id"] =
            Value::String("agent:example:other:v1".to_string());

        let (decision, _event) = evaluate_request(&request, now());
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "validate_token_binding");
    }

    #[test]
    fn denies_on_malformed_request() {
        let request = json!({ "foo": "bar" });
        let (decision, _event) = evaluate_request(&request, now());
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "normalize_request");
    }

    #[test]
    fn denies_on_unsupported_spec_version() {
        let mut request = valid_request();
        request["spec_version"] = Value::String("9.9".to_string());
        let (decision, _event) = evaluate_request(&request, now());
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "normalize_request");
    }

    #[test]
    fn appends_audit_events_as_jsonl() {
        let (decision, event) = evaluate_request(&valid_request(), now());
        assert!(decision.allowed);

        let path = std::env::temp_dir().join(format!(
            "agentauth_audit_{}.jsonl",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        ));

        append_audit_event(&path, &event).expect("audit append should succeed");
        let contents = std::fs::read_to_string(&path).expect("audit file should exist");
        std::fs::remove_file(&path).expect("temporary audit file should be removable");
        assert!(contents.contains("\"allowed\":true"));
        assert!(contents.contains("\"token_id\":\"dlg_01J0EXAMPLE\""));
    }
}
