/// End-to-end integration test: spins up a real axum server with the
/// `DelegatedLayer` middleware and exercises it via `DelegatedClient`.
///
/// The test verifies:
/// - A valid request is allowed (200 OK + `allowed: true`).
/// - A request whose action is not in the token's allowed list is denied (403).
/// - A nonce-replayed request is denied (403).
use axum::{Json, Router, routing::post};
use delegated::{
    DelegatedClient, DelegatedLayerBuilder, InMemoryAsyncTrustState, JsonlFileAuditSink,
    RequestEnvelope,
    issuance::{AgentIdentityDocumentBuilder, DelegationTokenBuilder, RequestEnvelopeBuilder},
};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;

fn build_envelope(action: &str, nonce_suffix: &str) -> RequestEnvelope {
    use ed25519_dalek::SigningKey;
    let key = SigningKey::from_bytes(&[55u8; 32]);

    let doc = AgentIdentityDocumentBuilder::new()
        .agent_id("agent:integration:scheduler:v1")
        .owner_id("org:integration")
        .issuer("https://trust.integration.test")
        .identity_type("spiffe")
        .subject("spiffe://integration.test/agents/scheduler")
        .key_id("key-integration-01")
        .supported_protocol("http")
        .supported_auth_method("delegation_token")
        .endpoint("http", "https://agents.integration.test/scheduler")
        .build_and_sign(&key)
        .expect("identity document build should succeed");

    let nonce = format!("nonce-integration-{nonce_suffix}");
    let token = DelegationTokenBuilder::new()
        .issuer("https://trust.integration.test")
        .agent_id("agent:integration:scheduler:v1")
        .delegator_id("user:integration-alice")
        .owner_id("org:integration")
        .audience("tool:integration-calendar")
        .allowed_action("calendar.create_event")
        .key_id("key-integration-01")
        .nonce(nonce)
        .expires_in(chrono::Duration::hours(1))
        .build_and_sign(&key)
        .expect("token build should succeed");

    RequestEnvelopeBuilder::new()
        .identity_document(doc)
        .token(token)
        .audience("tool:integration-calendar")
        .action(action)
        .build()
        .expect("envelope build should succeed")
}

async fn run_server() -> SocketAddr {
    let trust_state = Arc::new(InMemoryAsyncTrustState::new());
    let audit_path = std::env::temp_dir().join(format!(
        "delegated_integration_{}.jsonl",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time after epoch")
            .as_nanos()
    ));
    let sink = Arc::new(JsonlFileAuditSink::new(audit_path));

    let layer = DelegatedLayerBuilder::new(trust_state, sink).build();
    run_server_with_layer(layer).await
}

async fn run_server_with_limit(max_body_bytes: usize) -> SocketAddr {
    let trust_state = Arc::new(InMemoryAsyncTrustState::new());
    let audit_path = std::env::temp_dir().join(format!(
        "delegated_integration_limit_{}.jsonl",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time after epoch")
            .as_nanos()
    ));
    let sink = Arc::new(JsonlFileAuditSink::new(audit_path));

    let layer = DelegatedLayerBuilder::new(trust_state, sink)
        .with_max_body_bytes(max_body_bytes)
        .build();
    run_server_with_layer(layer).await
}

async fn run_server_with_layer(layer: delegated::DelegatedLayer) -> SocketAddr {
    let app = Router::new()
        .route(
            "/trust",
            post(|| async {
                Json(json!({"allowed": true, "stage": "evaluate_policy", "reason": "request authorized"}))
            }),
        )
        .layer(layer);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("should have local addr");

    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("server should run");
    });

    addr
}

#[tokio::test]
async fn allows_valid_request() {
    let addr = run_server().await;
    let client = DelegatedClient::new();
    let envelope = build_envelope("calendar.create_event", "allow-1");
    let url = format!("http://{addr}/trust");

    let resp = client
        .evaluate_http(&url, &envelope)
        .await
        .expect("request should complete");

    assert!(
        resp.is_allowed(),
        "expected allow, got: {} / {}",
        resp.stage,
        resp.reason
    );
    assert_eq!(resp.status_code, 200);
}

#[tokio::test]
async fn denies_unauthorized_action() {
    let addr = run_server().await;
    let client = DelegatedClient::new();
    let envelope = build_envelope("calendar.delete_event", "deny-action-1");
    let url = format!("http://{addr}/trust");

    let resp = client
        .evaluate_http(&url, &envelope)
        .await
        .expect("request should complete");

    assert!(!resp.is_allowed(), "expected deny for unauthorized action");
    assert_eq!(resp.status_code, 403);
}

#[tokio::test]
async fn denies_nonce_replay() {
    let addr = run_server().await;
    let client = DelegatedClient::new();
    let envelope = build_envelope("calendar.create_event", "replay-nonce");
    let url = format!("http://{addr}/trust");

    let first = client
        .evaluate_http(&url, &envelope)
        .await
        .expect("first request should complete");
    assert!(first.is_allowed(), "first request should be allowed");

    let second = client
        .evaluate_http(&url, &envelope)
        .await
        .expect("second request should complete");
    assert!(!second.is_allowed(), "nonce replay should be denied");
    assert_eq!(second.status_code, 403);
    assert_eq!(second.reason, "delegation token nonce replay detected");
}

#[tokio::test]
async fn denies_oversized_body_with_413() {
    let addr = run_server_with_limit(128).await;
    let url = format!("http://{addr}/trust");
    let client = reqwest::Client::new();

    let oversized = "x".repeat(8_192);
    let body = json!({
        "agent_id": oversized,
        "delegator_id": "user:integration-alice"
    });

    let response = client
        .post(url)
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .expect("oversized request should return response");

    assert_eq!(response.status().as_u16(), 413);
}
