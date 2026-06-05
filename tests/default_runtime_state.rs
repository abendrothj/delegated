use chrono::Utc;
use delegated::issuance::{
    AgentIdentityDocumentBuilder, DelegationTokenBuilder, RequestEnvelopeBuilder,
};
use delegated::{evaluate_request, models::TrustProfile};
use ed25519_dalek::SigningKey;
use serde_json::to_value;

fn signed_request_with_nonce(nonce: &str) -> serde_json::Value {
    let key = SigningKey::from_bytes(&[13u8; 32]);
    let doc = AgentIdentityDocumentBuilder::new()
        .agent_id("agent:example:scheduler:v1")
        .owner_id("org:example")
        .issuer("https://trust.example.ai")
        .identity_type("spiffe")
        .subject("spiffe://example.ai/agents/scheduler")
        .key_id("key-2026-01")
        .supported_protocol("http")
        .supported_auth_method("delegation_token")
        .endpoint("http", "https://agents.example.ai/scheduler")
        .build_and_sign(&key)
        .expect("identity document should build");
    let token = DelegationTokenBuilder::new()
        .issuer("https://trust.example.ai")
        .agent_id("agent:example:scheduler:v1")
        .delegator_id("user:alice")
        .owner_id("org:example")
        .audience("tool:google-calendar")
        .allowed_action("calendar.create_event")
        .nonce(nonce)
        .key_id("key-2026-01")
        .expires_in(chrono::Duration::hours(1))
        .build_and_sign(&key)
        .expect("delegation token should build");
    let envelope = RequestEnvelopeBuilder::new()
        .profile(TrustProfile::Developer)
        .identity_document(doc)
        .token(token)
        .audience("tool:google-calendar")
        .action("calendar.create_event")
        .build()
        .expect("request envelope should build");
    to_value(envelope).expect("serialization should succeed")
}

#[test]
fn default_runtime_blocks_replay_across_calls() {
    let nonce = format!(
        "default-runtime-replay-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_nanos()
    );
    let request = signed_request_with_nonce(&nonce);
    let now = Utc::now();

    let (first, _) = evaluate_request(&request, now);
    let (second, _) = evaluate_request(&request, now);

    assert!(first.allowed, "first evaluation should allow");
    assert!(!second.allowed, "second evaluation should deny replay");
    assert_eq!(second.stage, "enforce_revocation_and_redelegation");
}
