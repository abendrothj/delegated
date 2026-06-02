use agentauth::models::{
    AgentEndpoint, AgentIdentityDocument, DelegationToken, PublicKeyRecord, RuntimeContext,
};
use agentauth::{
    InMemoryTrustState, JsonlFileAuditSink, RequestEnvelope, TOKEN_SIGNATURE_ALG_ED25519,
    handle_http_json_request_with_state, sign_delegation_token, sign_identity_document,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{TimeZone, Utc};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

fn signed_request_value(request_id: &str, nonce: &str) -> Value {
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
        token_id: format!("dlg_{request_id}"),
        issuer: "https://trust.example.ai".to_string(),
        agent_id: "agent:example:scheduler:v1".to_string(),
        delegator_id: "user:jake-abendroth".to_string(),
        owner_id: "org:example".to_string(),
        audience: vec!["tool:google-calendar".to_string(), "tool:gmail".to_string()],
        allowed_actions: vec![
            "calendar.create_event".to_string(),
            "gmail.send_message".to_string(),
        ],
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
        intent: Some("schedule_demo_and_send_confirmation".to_string()),
        nonce: nonce.to_string(),
        key_id: "key-2026-01".to_string(),
        signature_alg: TOKEN_SIGNATURE_ALG_ED25519.to_string(),
        signature: String::new(),
    };
    token.signature = sign_delegation_token(&token, &key).expect("token signing should work");

    let request = RequestEnvelope {
        spec_version: "0.1".to_string(),
        kind: "TrustRequestEnvelope".to_string(),
        request_id: Some(request_id.to_string()),
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
            cognitive_judge_scores_bps: Some(vec![9300, 9100]),
            cognitive_challenge_pass_bps: Some(9200),
            reputation_score_bps: Some(8300),
            risk_challenge_passed: None,
            extra_approval_granted: None,
        },
        identity_document: Some(identity_document),
        token,
    };

    serde_json::to_value(request).expect("request serialization should work")
}

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 6, 1, 20, 20, 0)
        .single()
        .expect("valid timestamp")
}

#[test]
fn allows_signed_request_end_to_end() {
    let path = std::env::temp_dir().join(format!(
        "agentauth_conformance_allow_{}.jsonl",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_nanos()
    ));
    let sink = JsonlFileAuditSink::new(path.clone());
    let mut state = InMemoryTrustState::new();
    let body = signed_request_value("req_conf_allow", "nonce-allow").to_string();

    let response = handle_http_json_request_with_state(&body, now(), &sink, &mut state);
    assert_eq!(response.status_code, 200);
    assert_eq!(response.body["allowed"], json!(true));

    std::fs::remove_file(path).expect("temporary audit file should be removable");
}

#[test]
fn denies_tampered_signature_end_to_end() {
    let path = std::env::temp_dir().join(format!(
        "agentauth_conformance_tamper_{}.jsonl",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_nanos()
    ));
    let sink = JsonlFileAuditSink::new(path.clone());
    let mut state = InMemoryTrustState::new();
    let mut request = signed_request_value("req_conf_tamper", "nonce-tamper");
    request["delegation_token"]["signature"] = json!("tampered-signature");

    let response =
        handle_http_json_request_with_state(&request.to_string(), now(), &sink, &mut state);
    assert_eq!(response.status_code, 403);
    assert_eq!(response.body["stage"], json!("verify_signatures"));

    std::fs::remove_file(path).expect("temporary audit file should be removable");
}

#[test]
fn denies_revoked_token_end_to_end() {
    let path = std::env::temp_dir().join(format!(
        "agentauth_conformance_revoke_{}.jsonl",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_nanos()
    ));
    let sink = JsonlFileAuditSink::new(path.clone());
    let mut state = InMemoryTrustState::new();
    let request = signed_request_value("req_conf_revoke", "nonce-revoke");
    let token_id = request["delegation_token"]["token_id"]
        .as_str()
        .expect("token_id must be present");
    state.revoke_token(token_id.to_string());

    let response =
        handle_http_json_request_with_state(&request.to_string(), now(), &sink, &mut state);
    assert_eq!(response.status_code, 403);
    assert_eq!(
        response.body["reason"],
        json!("delegation token has been revoked")
    );

    std::fs::remove_file(path).expect("temporary audit file should be removable");
}

#[test]
fn denies_nonce_replay_end_to_end() {
    let path = std::env::temp_dir().join(format!(
        "agentauth_conformance_replay_{}.jsonl",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_nanos()
    ));
    let sink = JsonlFileAuditSink::new(path.clone());
    let mut state = InMemoryTrustState::new();
    let body = signed_request_value("req_conf_replay", "nonce-replay").to_string();

    let first = handle_http_json_request_with_state(&body, now(), &sink, &mut state);
    let second = handle_http_json_request_with_state(&body, now(), &sink, &mut state);

    assert_eq!(first.status_code, 200);
    assert_eq!(second.status_code, 403);
    assert_eq!(
        second.body["reason"],
        json!("delegation token nonce replay detected")
    );

    std::fs::remove_file(path).expect("temporary audit file should be removable");
}

#[test]
fn writes_allow_and_deny_audit_events_end_to_end() {
    let path = std::env::temp_dir().join(format!(
        "agentauth_conformance_audit_{}.jsonl",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_nanos()
    ));
    let sink = JsonlFileAuditSink::new(path.clone());
    let mut state = InMemoryTrustState::new();

    let allow_body = signed_request_value("req_conf_audit_allow", "nonce-audit-allow").to_string();
    let mut deny_body = signed_request_value("req_conf_audit_deny", "nonce-audit-deny");
    deny_body["runtime_context"]["reputation_score_bps"] = json!(1000);
    deny_body["runtime_context"]["risk_challenge_passed"] = json!(false);
    deny_body["runtime_context"]["extra_approval_granted"] = json!(false);

    let allow = handle_http_json_request_with_state(&allow_body, now(), &sink, &mut state);
    let deny =
        handle_http_json_request_with_state(&deny_body.to_string(), now(), &sink, &mut state);

    assert_eq!(allow.status_code, 200);
    assert_eq!(deny.status_code, 403);

    let contents = std::fs::read_to_string(&path).expect("audit file should exist");
    assert_eq!(contents.lines().count(), 2);
    assert!(contents.contains("\"allowed\":true"));
    assert!(contents.contains("\"allowed\":false"));
    std::fs::remove_file(path).expect("temporary audit file should be removable");
}
