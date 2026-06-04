use chrono::{Duration, Utc};
use delegated::{
    AgentIdentityDocumentBuilder, DelegationTokenBuilder, RequestEnvelopeBuilder, evaluate_request,
};
use ed25519_dalek::SigningKey;
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iterations = std::env::args()
        .nth(1)
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(10_000);

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
    let request_value = serde_json::to_value(request)?;

    let start = Instant::now();
    let mut allowed = 0usize;
    for _ in 0..iterations {
        let (decision, _event) = evaluate_request(&request_value, Utc::now());
        if decision.allowed {
            allowed += 1;
        }
    }
    let elapsed = start.elapsed();
    let secs = elapsed.as_secs_f64();
    let rps = if secs > 0.0 {
        iterations as f64 / secs
    } else {
        f64::INFINITY
    };

    println!("iterations: {iterations}");
    println!("allowed: {allowed}");
    println!("elapsed_ms: {:.3}", secs * 1000.0);
    println!("evaluations_per_sec: {:.1}", rps);
    Ok(())
}
