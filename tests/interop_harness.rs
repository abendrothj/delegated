use agentauth::models::{
    AgentEndpoint, AgentIdentityDocument, DelegationToken, PublicKeyRecord, RequestEnvelope,
    RuntimeContext, TrustProfile,
};
use agentauth::{
    A2aProtocolRequest, InMemoryTrustState, JsonlFileAuditSink, SharedTrustClaims,
    TOKEN_SIGNATURE_ALG_ED25519, handle_a2a_request_with_state,
    handle_http_json_request_with_state, handle_mcp_jsonrpc_request_with_state,
    sign_delegation_token, sign_identity_document,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{TimeZone, Utc};
use ed25519_dalek::SigningKey;
use serde_json::json;

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[77u8; 32])
}

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 6, 1, 20, 20, 0)
        .single()
        .expect("valid timestamp")
}

fn signed_request(
    nonce: &str,
    profile: TrustProfile,
    identity_type: &str,
    subject: &str,
    supported_auth_methods: Vec<String>,
    supported_protocols: Vec<String>,
) -> RequestEnvelope {
    let key = signing_key();
    let mut identity_document = AgentIdentityDocument {
        spec_version: "0.1".to_string(),
        kind: "AgentIdentityDocument".to_string(),
        agent_id: "agent:example:scheduler:v1".to_string(),
        display_name: Some("example Scheduler Agent".to_string()),
        owner_id: "org:example".to_string(),
        issuer: "https://trust.example.ai".to_string(),
        identity_type: identity_type.to_string(),
        subject: subject.to_string(),
        public_keys: vec![PublicKeyRecord {
            kid: "key-2026-01".to_string(),
            kty: "OKP".to_string(),
            crv: Some(TOKEN_SIGNATURE_ALG_ED25519.to_string()),
            x: Some(Base64UrlUnpadded::encode_string(
                &key.verifying_key().to_bytes(),
            )),
        }],
        supported_protocols,
        supported_auth_methods,
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
        token_id: format!("dlg_{nonce}"),
        issuer: "https://trust.example.ai".to_string(),
        agent_id: "agent:example:scheduler:v1".to_string(),
        delegator_id: format!("user:jake-abendroth:{nonce}"),
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
        intent: Some("schedule_demo".to_string()),
        nonce: nonce.to_string(),
        key_id: "key-2026-01".to_string(),
        signature_alg: TOKEN_SIGNATURE_ALG_ED25519.to_string(),
        signature: String::new(),
    };
    token.signature = sign_delegation_token(&token, &key).expect("token signing should work");

    RequestEnvelope {
        spec_version: "0.1".to_string(),
        kind: "TrustRequestEnvelope".to_string(),
        request_id: Some(format!("req_{nonce}")),
        profile,
        agent_id: "agent:example:scheduler:v1".to_string(),
        delegator_id: format!("user:jake-abendroth:{nonce}"),
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
    }
}

fn run_across_adapters(envelope: RequestEnvelope) -> (u16, Option<serde_json::Value>, String) {
    let claims: SharedTrustClaims = envelope.clone().into();
    let http_body =
        serde_json::to_string(&envelope).expect("HTTP request serialization should work");
    let mcp_body = mcp_body(claims.clone());
    let a2a_body = a2a_body(claims);
    let sink_path = std::env::temp_dir().join(format!(
        "agentauth_interop_{}.jsonl",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_nanos()
    ));
    let sink = JsonlFileAuditSink::new(sink_path.clone());
    let mut http_state = InMemoryTrustState::new();
    let mut mcp_state = InMemoryTrustState::new();
    let mut a2a_state = InMemoryTrustState::new();

    let http = handle_http_json_request_with_state(&http_body, now(), &sink, &mut http_state);
    let mcp = handle_mcp_jsonrpc_request_with_state(&mcp_body, now(), &sink, &mut mcp_state);
    let a2a = handle_a2a_request_with_state(&a2a_body, now(), &sink, &mut a2a_state);
    let _ = std::fs::remove_file(sink_path);
    (http.status_code, mcp.error, a2a.status)
}

fn mcp_body(claims: SharedTrustClaims) -> String {
    json!({
        "jsonrpc":"2.0",
        "id":"interop-mcp",
        "method":"tools.call",
        "params":{
            "_trust": claims,
            "_payload": {"tool":"calendar.create_event"}
        }
    })
    .to_string()
}

fn a2a_body(claims: SharedTrustClaims) -> String {
    serde_json::to_string(&A2aProtocolRequest {
        message_id: "interop-a2a".to_string(),
        protocol_version: "2026-06-01".to_string(),
        message_type: "task.request".to_string(),
        trust_claims: claims,
        payload: json!({"task":"schedule"}),
    })
    .expect("A2A serialization should work")
}

#[test]
fn produces_equivalent_allow_decisions_across_http_mcp_a2a() {
    let envelope = signed_request(
        "interop-allow",
        TrustProfile::Developer,
        "spiffe",
        "spiffe://example.ai/agents/scheduler",
        vec!["delegation_token".to_string()],
        vec!["http".to_string(), "mcp".to_string(), "a2a".to_string()],
    );
    let (http_status, mcp_error, a2a_status) = run_across_adapters(envelope);

    assert_eq!(http_status, 200);
    assert!(mcp_error.is_none());
    assert_eq!(a2a_status, "ok");
}

#[test]
fn produces_equivalent_deny_decisions_across_http_mcp_a2a() {
    let mut envelope = signed_request(
        "interop-deny",
        TrustProfile::Developer,
        "spiffe",
        "spiffe://example.ai/agents/scheduler",
        vec!["delegation_token".to_string()],
        vec!["http".to_string(), "mcp".to_string(), "a2a".to_string()],
    );
    envelope.runtime_context.reputation_score_bps = Some(1000);
    envelope.runtime_context.risk_challenge_passed = Some(false);
    envelope.runtime_context.extra_approval_granted = Some(false);

    let (http_status, mcp_error, a2a_status) = run_across_adapters(envelope);

    assert_eq!(http_status, 403);
    assert_eq!(
        mcp_error
            .as_ref()
            .and_then(|e| e.get("data"))
            .and_then(|d| d.get("reason")),
        Some(&json!(
            "low reputation requires additional challenge pass or explicit approval"
        ))
    );
    assert_eq!(a2a_status, "denied");
}

#[test]
fn produces_oidc_profile_allow_parity_across_http_mcp_a2a() {
    let envelope = signed_request(
        "interop-oidc-allow",
        TrustProfile::Oidc,
        "oidc",
        "service-account:calendar-worker",
        vec!["delegation_token".to_string()],
        vec!["http".to_string(), "mcp".to_string(), "a2a".to_string()],
    );
    let (http_status, mcp_error, a2a_status) = run_across_adapters(envelope);
    assert_eq!(http_status, 200);
    assert!(mcp_error.is_none());
    assert_eq!(a2a_status, "ok");
}

#[test]
fn produces_oidc_profile_deny_parity_across_http_mcp_a2a() {
    let envelope = signed_request(
        "interop-oidc-deny",
        TrustProfile::Oidc,
        "oidc",
        "service-account:calendar-worker",
        vec!["oauth_bearer".to_string()],
        vec!["http".to_string(), "mcp".to_string(), "a2a".to_string()],
    );
    let (http_status, mcp_error, a2a_status) = run_across_adapters(envelope);
    assert_eq!(http_status, 403);
    assert_eq!(
        mcp_error
            .as_ref()
            .and_then(|e| e.get("data"))
            .and_then(|d| d.get("reason")),
        Some(&json!(
            "profile requires identity_document.supported_auth_methods to include delegation_token"
        ))
    );
    assert_eq!(a2a_status, "denied");
}

#[test]
fn produces_spiffe_profile_allow_parity_across_http_mcp_a2a() {
    let envelope = signed_request(
        "interop-spiffe-allow",
        TrustProfile::Spiffe,
        "spiffe",
        "spiffe://example.ai/agents/scheduler",
        vec!["delegation_token".to_string()],
        vec!["http".to_string(), "mcp".to_string(), "a2a".to_string()],
    );
    let (http_status, mcp_error, a2a_status) = run_across_adapters(envelope);
    assert_eq!(http_status, 200);
    assert!(mcp_error.is_none());
    assert_eq!(a2a_status, "ok");
}

#[test]
fn produces_spiffe_profile_deny_parity_across_http_mcp_a2a() {
    let envelope = signed_request(
        "interop-spiffe-deny",
        TrustProfile::Spiffe,
        "spiffe",
        "spiffe://example.ai/agents/scheduler",
        vec!["delegation_token".to_string()],
        vec!["smtp".to_string()],
    );
    let (http_status, mcp_error, a2a_status) = run_across_adapters(envelope);
    assert_eq!(http_status, 403);
    assert_eq!(
        mcp_error
            .as_ref()
            .and_then(|e| e.get("data"))
            .and_then(|d| d.get("reason")),
        Some(&json!(
            "SPIFFE profile requires at least one supported protocol from http|mcp|a2a"
        ))
    );
    assert_eq!(a2a_status, "denied");
}
