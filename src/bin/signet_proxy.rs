//! Transparent MCP sidecar proxy.
//!
//! `tools/call` and `tools.call` requests are intercepted and run through the
//! full signet trust pipeline. All other MCP methods (`tools/list`, `prompts/get`,
//! `resources/read`, etc.) are forwarded unchanged to the upstream server so
//! client discovery and context loading continue to work.
//!
//! # Configuration (environment variables)
//!
//! | Variable                | Default               | Description                        |
//! |-------------------------|-----------------------|------------------------------------|
//! | `SIGNET_UPSTREAM_URL`   | **required**          | Upstream MCP server base URL       |
//! | `SIGNET_LISTEN_ADDR`    | `0.0.0.0:7777`        | Address to bind                    |
//! | `SIGNET_AUDIT_LOG_PATH` | `signet-audit.jsonl`  | Append-only audit log path         |
//! | `SIGNET_MAX_BODY_BYTES` | `1048576` (1 MiB)     | Maximum request body size          |
//!
//! # Usage
//!
//! ```sh
//! SIGNET_UPSTREAM_URL=http://localhost:9000 signet-proxy
//! ```
//!
//! Point your MCP client at `http://localhost:7777` instead of the upstream.
//! The proxy enforces trust on every tool call and passes everything else through.

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderName, StatusCode, header},
    response::Response,
    routing::any,
};
use chrono::Utc;
use signet::{
    HostContext, InMemoryAsyncTrustState, JsonlFileAuditSink, McpAdapterDecision,
    handle_mcp_jsonrpc_request_with_async_state,
};
use std::sync::Arc;

const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:7777";
const DEFAULT_AUDIT_LOG: &str = "signet-audit.jsonl";
const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;

struct AppState {
    upstream_url: String,
    trust_state: InMemoryAsyncTrustState,
    audit_sink: JsonlFileAuditSink,
    host_context: HostContext,
    http_client: reqwest::Client,
    max_body_bytes: usize,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let upstream_url = std::env::var("SIGNET_UPSTREAM_URL")
        .map_err(|_| "SIGNET_UPSTREAM_URL is required")?;
    let listen_addr = std::env::var("SIGNET_LISTEN_ADDR")
        .unwrap_or_else(|_| DEFAULT_LISTEN_ADDR.to_string());
    let audit_log = std::env::var("SIGNET_AUDIT_LOG_PATH")
        .unwrap_or_else(|_| DEFAULT_AUDIT_LOG.to_string());
    let max_body_bytes = std::env::var("SIGNET_MAX_BODY_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_BODY_BYTES);

    let state = Arc::new(AppState {
        upstream_url: upstream_url.trim_end_matches('/').to_string(),
        trust_state: InMemoryAsyncTrustState::new(),
        audit_sink: JsonlFileAuditSink::new(audit_log),
        host_context: HostContext::default(),
        http_client: reqwest::Client::new(),
        max_body_bytes,
    });

    let app = Router::new()
        .fallback(any(proxy_handler))
        .with_state(Arc::clone(&state));

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    eprintln!(
        "signet-proxy listening on {}  upstream={}",
        listen_addr, upstream_url
    );
    axum::serve(listener, app).await?;
    Ok(())
}

async fn proxy_handler(State(state): State<Arc<AppState>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();

    // Buffer body with size limit.
    let bytes = match axum::body::to_bytes(body, state.max_body_bytes).await {
        Ok(b) => b,
        Err(_) => {
            return plain_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body exceeds size limit",
            );
        }
    };

    // Only attempt trust evaluation for JSON bodies — pass everything else through.
    let raw_str = match std::str::from_utf8(&bytes) {
        Ok(s) => s,
        Err(_) => return forward_to_upstream(&state, &parts, bytes).await,
    };

    let now = Utc::now();
    let decision = handle_mcp_jsonrpc_request_with_async_state(
        raw_str,
        now,
        &state.audit_sink,
        &state.trust_state,
        &state.host_context,
    )
    .await;

    match decision {
        McpAdapterDecision::Respond(response) => {
            // Return the trust evaluation result (allow or deny) as a JSON-RPC response.
            // Per JSON-RPC 2.0, HTTP status is always 200 — the error lives in the body.
            let body_bytes = serde_json::to_vec(&response)
                .expect("McpJsonRpcResponse serialization should succeed");
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body_bytes))
                .expect("response builder should succeed")
        }
        McpAdapterDecision::PassThrough => {
            // Non-trust-gated method (tools/list, prompts/get, resources/read, etc.):
            // forward the original request to the upstream server unchanged.
            forward_to_upstream(&state, &parts, bytes).await
        }
    }
}

async fn forward_to_upstream(
    state: &AppState,
    parts: &axum::http::request::Parts,
    body: axum::body::Bytes,
) -> Response {
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let upstream_url = format!("{}{}", state.upstream_url, path_and_query);

    let mut request_builder = state.http_client.post(&upstream_url);
    for (name, value) in &parts.headers {
        if !is_hop_by_hop(name) {
            request_builder = request_builder.header(name.as_str(), value.as_bytes());
        }
    }

    let upstream_result = request_builder.body(body).send().await;

    match upstream_result {
        Ok(resp) => {
            let status = resp.status();
            let resp_headers = resp.headers().clone();
            match resp.bytes().await {
                Ok(resp_body) => {
                    let mut builder = Response::builder().status(status.as_u16());
                    for (name, value) in &resp_headers {
                        if !is_hop_by_hop(name) {
                            builder = builder.header(name.as_str(), value.as_bytes());
                        }
                    }
                    builder
                        .body(Body::from(resp_body))
                        .unwrap_or_else(|_| {
                            plain_response(StatusCode::INTERNAL_SERVER_ERROR, "response build failed")
                        })
                }
                Err(e) => plain_response(
                    StatusCode::BAD_GATEWAY,
                    &format!("upstream read failed: {e}"),
                ),
            }
        }
        Err(e) => plain_response(
            StatusCode::BAD_GATEWAY,
            &format!("upstream request failed: {e}"),
        ),
    }
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    name == header::CONNECTION
        || name == header::TRANSFER_ENCODING
        || name == header::TE
        || name == header::TRAILER
        || name == header::UPGRADE
        || name.as_str() == "keep-alive"
        || name.as_str() == "proxy-connection"
        || name.as_str() == "proxy-authenticate"
        || name.as_str() == "proxy-authorization"
}

fn plain_response(status: StatusCode, message: &str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(message.to_string()))
        .expect("plain response builder should succeed")
}
