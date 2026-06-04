//! End-to-end example: axum HTTP server with delegated trust middleware.
//!
//! Run with:
//!     cargo run --example axum_server --features axum
//!
//! Then send a trust-validated request:
//!     curl -s -X POST http://localhost:3000/calendar \
//!       -H "Content-Type: application/json" \
//!       -d "$(cargo run --example build_request 2>/dev/null)" | jq .

use delegated::adapters::axum_layer::{DelegatedLayer, DelegatedLayerBuilder};
use delegated::revocation_async::InMemoryAsyncTrustState;
use delegated::JsonlFileAuditSink;
use axum::{Json, Router, routing::post};
use serde_json::{Value, json};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let trust_state = Arc::new(InMemoryAsyncTrustState::new());
    let audit_sink = Arc::new(JsonlFileAuditSink::new(
        std::env::temp_dir().join("delegated_axum_example.jsonl"),
    ));

    let delegated_layer = DelegatedLayerBuilder::new(trust_state, audit_sink).build();

    let app = Router::new()
        .route("/calendar", post(handle_calendar))
        .layer(delegated_layer);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("failed to bind to port 3000");

    println!("delegated axum example listening on http://0.0.0.0:3000");
    axum::serve(listener, app)
        .await
        .expect("server failed");
}

async fn handle_calendar(Json(body): Json<Value>) -> Json<Value> {
    // The DelegatedLayer has already verified trust — any request reaching here is authorized.
    let action = body
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    Json(json!({
        "status": "ok",
        "message": format!("calendar action '{}' accepted", action)
    }))
}
