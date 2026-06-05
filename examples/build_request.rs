use chrono::Duration;
use ed25519_dalek::SigningKey;
use signet::issuance::{
    AgentIdentityDocumentBuilder, DelegationTokenBuilder, RequestEnvelopeBuilder,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = SigningKey::from_bytes(&[42u8; 32]);

    let identity = AgentIdentityDocumentBuilder::new()
        .agent_id("agent:example:scheduler:v1")
        .owner_id("org:example")
        .issuer("https://trust.example.ai")
        .identity_type("spiffe")
        .subject("spiffe://example.ai/agents/scheduler")
        .key_id("key-2026-01")
        .supported_protocol("http")
        .supported_auth_method("delegation_token")
        .endpoint("http", "https://agents.example.ai/scheduler")
        .build_and_sign(&key)?;

    let token = DelegationTokenBuilder::new()
        .issuer("https://trust.example.ai")
        .agent_id("agent:example:scheduler:v1")
        .delegator_id("user:alice")
        .owner_id("org:example")
        .audience("tool:google-calendar")
        .allowed_action("calendar.create_event")
        .key_id("key-2026-01")
        .expires_in(Duration::minutes(30))
        .build_and_sign(&key)?;

    let request = RequestEnvelopeBuilder::new()
        .identity_document(identity)
        .token(token)
        .audience("tool:google-calendar")
        .action("calendar.create_event")
        .build()?;

    println!("{}", serde_json::to_string(&request)?);
    Ok(())
}
