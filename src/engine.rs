use crate::audit::{AuditSink, JsonlFileAuditSink, write_audit_event};
use crate::models::{AuditEvent, Decision, PolicyCheck, RequestEnvelope, Violation};
use crate::policy::{evaluate_policy, simulate_policy};
use crate::profiles::validate_profile_compatibility;
use crate::revocation::{InMemoryTrustState, TrustStateStore};
use crate::stages::{
    enforce_revocation_and_redelegation, normalize_request, validate_identity_document_lifetime,
    validate_token_binding, validate_token_lifetime, verify_signatures,
};
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::io;
use std::path::Path;

pub fn evaluate_request(raw_request: &Value, now: DateTime<Utc>) -> (Decision, AuditEvent) {
    let mut trust_state = InMemoryTrustState::new();
    evaluate_request_with_state(raw_request, now, &mut trust_state)
}

pub fn evaluate_request_with_state(
    raw_request: &Value,
    now: DateTime<Utc>,
    trust_state: &mut dyn TrustStateStore,
) -> (Decision, AuditEvent) {
    let result = normalize_request(raw_request)
        .and_then(validate_profile_compatibility)
        .and_then(verify_signatures)
        .and_then(|envelope| validate_identity_document_lifetime(envelope, now))
        .and_then(|envelope| enforce_revocation_and_redelegation(envelope, trust_state))
        .and_then(|envelope| validate_token_lifetime(envelope, now))
        .and_then(validate_token_binding)
        .and_then(evaluate_policy);

    match result {
        Ok(envelope) => {
            let decision = Decision::allow("evaluate_policy", "request authorized");
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

pub fn simulate_request_policy(raw_request: &Value) -> Result<Vec<PolicyCheck>, Violation> {
    let envelope = normalize_request(raw_request)?;
    Ok(simulate_policy(&envelope))
}

pub fn append_audit_event(path: impl AsRef<Path>, event: &AuditEvent) -> io::Result<()> {
    let sink = JsonlFileAuditSink::new(path.as_ref().to_path_buf());
    write_audit_event(&sink, event)
}

pub fn evaluate_and_audit(
    raw_request: &Value,
    now: DateTime<Utc>,
    sink: &dyn AuditSink,
) -> io::Result<Decision> {
    let mut trust_state = InMemoryTrustState::new();
    evaluate_and_audit_with_state(raw_request, now, sink, &mut trust_state)
}

pub fn evaluate_and_audit_with_state(
    raw_request: &Value,
    now: DateTime<Utc>,
    sink: &dyn AuditSink,
    trust_state: &mut dyn TrustStateStore,
) -> io::Result<Decision> {
    let (decision, event) = evaluate_request_with_state(raw_request, now, trust_state);
    write_audit_event(sink, &event)?;
    Ok(decision)
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
    use serde_json::json;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 1, 20, 20, 0)
            .single()
            .expect("valid test timestamp")
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn valid_request() -> Value {
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
            token_id: "dlg_01J0EXAMPLE".to_string(),
            issuer: "https://trust.example.ai".to_string(),
            agent_id: "agent:example:scheduler:v1".to_string(),
            delegator_id: "user:jake-abendroth".to_string(),
            owner_id: "org:example".to_string(),
            audience: vec!["tool:google-calendar".to_string(), "tool:gmail".to_string()],
            allowed_actions: vec![
                "calendar.create_event".to_string(),
                "calendar.read_availability".to_string(),
                "gmail.send_message".to_string(),
            ],
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
            intent: Some("schedule_demo_and_send_confirmation".to_string()),
            nonce: "random-nonce".to_string(),
            key_id: "key-2026-01".to_string(),
            signature_alg: TOKEN_SIGNATURE_ALG_ED25519.to_string(),
            signature: String::new(),
        };
        token.signature =
            sign_delegation_token(&token, &key).expect("delegation signing should work");

        let envelope = RequestEnvelope {
            spec_version: "0.1".to_string(),
            kind: "TrustRequestEnvelope".to_string(),
            request_id: Some("req_123".to_string()),
            profile: TrustProfile::Developer,
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

        serde_json::to_value(envelope).expect("request serialization should work")
    }

    fn resign_token(request: &mut Value) {
        let key = signing_key();
        let mut token: DelegationToken =
            serde_json::from_value(request["delegation_token"].clone())
                .expect("token should parse");
        token.signature = sign_delegation_token(&token, &key).expect("token resign should work");
        request["delegation_token"] = serde_json::to_value(token).expect("token serialization");
    }

    fn resign_identity_document(request: &mut Value) {
        let key = signing_key();
        let mut identity: AgentIdentityDocument =
            serde_json::from_value(request["identity_document"].clone())
                .expect("identity document should parse");
        identity.signature =
            sign_identity_document(&identity, &key).expect("identity resign should work");
        request["identity_document"] =
            serde_json::to_value(identity).expect("identity serialization should work");
    }

    #[test]
    fn allows_valid_request() {
        let (decision, event) = evaluate_request(&valid_request(), now());
        assert!(decision.allowed);
        assert_eq!(decision.stage, "evaluate_policy");
        assert_eq!(event.allowed, true);
        assert_eq!(event.token_id.as_deref(), Some("dlg_01J0EXAMPLE"));
    }

    #[test]
    fn denies_when_action_not_allowed() {
        let mut request = valid_request();
        request["action"] = Value::String("calendar.delete_event".to_string());

        let (decision, event) = evaluate_request(&request, now());
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "evaluate_policy");
        assert_eq!(event.allowed, false);
    }

    #[test]
    fn denies_when_token_expired() {
        let mut request = valid_request();
        request["delegation_token"]["expires_at"] =
            Value::String("2026-06-01T20:15:00Z".to_string());
        resign_token(&mut request);

        let (decision, _event) = evaluate_request(&request, now());
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "validate_token_lifetime");
    }

    #[test]
    fn denies_when_identity_document_expired() {
        let mut request = valid_request();
        request["identity_document"]["expires_at"] =
            Value::String("2026-06-01T20:10:00Z".to_string());
        resign_identity_document(&mut request);
        let (decision, _event) = evaluate_request(&request, now());
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "validate_identity_document_lifetime");
    }

    #[test]
    fn denies_when_binding_mismatch() {
        let mut request = valid_request();
        request["delegator_id"] = Value::String("user:someone-else".to_string());

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
    fn denies_when_email_domain_not_allowed() {
        let mut request = valid_request();
        request["audience"] = Value::String("tool:gmail".to_string());
        request["action"] = Value::String("gmail.send_message".to_string());
        request["runtime_context"] = json!({
            "target_email": "receiver@outside.org",
            "cognitive_judge_scores_bps": [9300, 9100],
            "cognitive_challenge_pass_bps": 9200
        });
        request["delegation_token"]["resource_constraints"] = json!({
            "email_domain_allowlist": ["example.com"]
        });
        resign_token(&mut request);

        let (decision, _event) = evaluate_request(&request, now());
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "evaluate_policy");
        assert_eq!(
            decision.reason,
            "target email domain not allowed by token resource constraints"
        );
    }

    #[test]
    fn simulates_policy_checks() {
        let mut request = valid_request();
        request["runtime_context"] = json!({
            "requested_spend": 10,
            "spend_currency": "USD",
            "delegation_depth": 1,
            "cognitive_judge_scores_bps": [9300, 9100],
            "cognitive_challenge_pass_bps": 9200
        });
        request["delegation_token"]["max_spend"] = json!({
            "amount": 5,
            "currency": "USD"
        });
        request["delegation_token"]["max_delegation_depth"] = json!(0);
        resign_token(&mut request);

        let checks = simulate_request_policy(&request).expect("policy simulation should succeed");
        assert!(checks.iter().any(|check| !check.passed));
        assert!(
            checks
                .iter()
                .any(|check| check.name == "max_spend" && !check.passed)
        );
    }

    #[test]
    fn denies_when_cognitive_thresholds_fail() {
        let mut request = valid_request();
        request["runtime_context"]["cognitive_judge_scores_bps"] = json!([6000, 5800]);
        request["runtime_context"]["cognitive_challenge_pass_bps"] = json!(7000);

        let (decision, _event) = evaluate_request(&request, now());
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "evaluate_policy");
        assert_eq!(
            decision.reason,
            "cognitive average score is below hard-deny threshold"
        );
    }

    #[test]
    fn enforces_reputation_risk_multiplier() {
        let mut request = valid_request();
        request["runtime_context"]["reputation_score_bps"] = json!(3000);
        request["runtime_context"]["risk_challenge_passed"] = json!(false);
        request["runtime_context"]["extra_approval_granted"] = json!(false);

        let (decision, _event) = evaluate_request(&request, now());
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "evaluate_policy");
        assert_eq!(
            decision.reason,
            "low reputation requires additional challenge pass or explicit approval"
        );
    }

    #[test]
    fn denies_when_signature_verification_fails() {
        let mut request = valid_request();
        request["delegation_token"]["signature"] = json!("not-a-valid-signature");
        let (decision, _event) = evaluate_request(&request, now());
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "verify_signatures");
    }

    #[test]
    fn denies_when_identity_document_missing() {
        let mut request = valid_request();
        request["identity_document"] = Value::Null;
        let (decision, _event) = evaluate_request(&request, now());
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "validate_profile_compatibility");
    }

    #[test]
    fn denies_when_token_is_revoked() {
        let request = valid_request();
        let mut trust_state = InMemoryTrustState::new();
        trust_state.revoke_token("dlg_01J0EXAMPLE");

        let (decision, _event) = evaluate_request_with_state(&request, now(), &mut trust_state);
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "enforce_revocation_and_redelegation");
        assert_eq!(decision.reason, "delegation token has been revoked");
    }

    #[test]
    fn denies_nonce_replay_with_shared_state() {
        let request = valid_request();
        let mut trust_state = InMemoryTrustState::new();

        let (first, _) = evaluate_request_with_state(&request, now(), &mut trust_state);
        let (second, _) = evaluate_request_with_state(&request, now(), &mut trust_state);

        assert!(first.allowed);
        assert!(!second.allowed);
        assert_eq!(second.stage, "enforce_revocation_and_redelegation");
        assert_eq!(second.reason, "delegation token nonce replay detected");
    }

    #[test]
    fn fails_closed_when_revocation_backend_unavailable() {
        let request = valid_request();
        let mut trust_state = InMemoryTrustState::new();
        trust_state.set_backend_available(false);

        let (decision, _) = evaluate_request_with_state(&request, now(), &mut trust_state);
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "enforce_revocation_and_redelegation");
        assert_eq!(
            decision.reason,
            "revocation backend unavailable (fail-closed)"
        );
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

    #[test]
    fn evaluates_and_writes_allow_and_deny_audits() {
        let path = std::env::temp_dir().join(format!(
            "agentauth_sink_{}.jsonl",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        ));
        let sink = JsonlFileAuditSink::new(path.clone());

        let allow_decision =
            evaluate_and_audit(&valid_request(), now(), &sink).expect("allow path should write");
        assert!(allow_decision.allowed);

        let mut deny_request = valid_request();
        deny_request["action"] = Value::String("calendar.delete_event".to_string());
        let deny_decision =
            evaluate_and_audit(&deny_request, now(), &sink).expect("deny path should write");
        assert!(!deny_decision.allowed);

        let contents = std::fs::read_to_string(&path).expect("audit file should exist");
        std::fs::remove_file(&path).expect("temporary audit file should be removable");
        assert_eq!(contents.lines().count(), 2);
        assert!(contents.contains("\"allowed\":true"));
        assert!(contents.contains("\"allowed\":false"));
    }
}
