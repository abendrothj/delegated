#![cfg(feature = "client")]

use ed25519_dalek::SigningKey;
use serde_json::json;
use signet::issuance::{
    AgentIdentityDocumentBuilder, DelegationTokenBuilder, RequestEnvelopeBuilder,
};
use signet::{TrustClient, models::TrustProfile};

fn build_envelope() -> signet::models::RequestEnvelope {
    let key = SigningKey::from_bytes(&[29u8; 32]);
    let doc = AgentIdentityDocumentBuilder::new()
        .agent_id("agent:example:external-interop:v1")
        .owner_id("org:example")
        .issuer("https://trust.example.ai")
        .identity_type("spiffe")
        .subject("spiffe://example.ai/agents/external-interop")
        .key_id("key-2026-interop")
        .supported_protocol("http")
        .supported_protocol("mcp")
        .supported_protocol("a2a")
        .supported_auth_method("delegation_token")
        .endpoint("http", "https://agents.example.ai/external-interop")
        .build_and_sign(&key)
        .expect("identity document should build");
    let token = DelegationTokenBuilder::new()
        .issuer("https://trust.example.ai")
        .agent_id("agent:example:external-interop:v1")
        .delegator_id("user:alice")
        .owner_id("org:example")
        .audience("tool:google-calendar")
        .allowed_action("calendar.create_event")
        .key_id("key-2026-interop")
        .expires_in(chrono::Duration::hours(1))
        .build_and_sign(&key)
        .expect("delegation token should build");
    RequestEnvelopeBuilder::new()
        .profile(TrustProfile::Developer)
        .identity_document(doc)
        .token(token)
        .audience("tool:google-calendar")
        .action("calendar.create_event")
        .build()
        .expect("request envelope should build")
}

#[tokio::test]
async fn validates_external_adapter_endpoints_when_configured() {
    let http_url = match std::env::var("SIGNET_INTEROP_HTTP_URL") {
        Ok(url) => url,
        Err(_) => return,
    };

    let envelope = build_envelope();
    let client = TrustClient::new();

    let http = client
        .evaluate_http(&http_url, &envelope)
        .await
        .expect("HTTP external interop call should succeed");
    assert!(
        http.is_allowed(),
        "expected allow from external HTTP adapter: {}",
        http.reason
    );

    if let Ok(mcp_url) = std::env::var("SIGNET_INTEROP_MCP_URL") {
        let mcp = client
            .evaluate_mcp(
                &mcp_url,
                json!("interop-external-mcp"),
                "tools.call",
                json!({"_payload":{"tool":"calendar.create_event"}}),
                &envelope,
            )
            .await
            .expect("MCP external interop call should succeed");
        assert!(
            mcp.is_allowed(),
            "expected allow from external MCP adapter: {:?}",
            mcp.response
        );
    }

    if let Ok(a2a_url) = std::env::var("SIGNET_INTEROP_A2A_URL") {
        let a2a = client
            .evaluate_a2a(
                &a2a_url,
                "interop-a2a-msg-1",
                "2026-06-01",
                "task.request",
                json!({"task":"schedule"}),
                &envelope,
            )
            .await
            .expect("A2A external interop call should succeed");
        assert!(
            a2a.is_allowed(),
            "expected allow from external A2A adapter: {:?}",
            a2a.response
        );
    }
}
