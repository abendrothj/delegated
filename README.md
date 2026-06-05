# delegated

Fail-closed trust evaluation for agentic AI systems.

`delegated` verifies delegation tokens and enforces policy on every agent action — before your tools, APIs, or downstream agents run anything. Drop it in as Tower middleware, call the standalone adapters, or use the client SDK to attach trust claims to outbound requests.

[![crates.io](https://img.shields.io/crates/v/delegated.svg)](https://crates.io/crates/delegated)
[![docs.rs](https://img.shields.io/docsrs/delegated)](https://docs.rs/crate/delegated/latest)
[![CI](https://github.com/abendrothj/delegated/actions/workflows/ci.yml/badge.svg)](https://github.com/abendrothj/delegated/actions/workflows/ci.yml)

## What it does

- **Verifies** Ed25519-signed delegation tokens and agent identity documents
- **Enforces** configurable policy: allowed actions, max spend, delegation depth, calendar constraints, email domain allowlists, cognitive and reputation gates
- **Blocks** revoked tokens, emergency-denied agents, nonce replays — fail-closed on backend errors
- **Audits** every decision to a structured JSONL sink
- **Issues** delegation tokens and identity documents via fluent builders with key rotation support

## Security and reliability

- Security policy and reporting: [`SECURITY.md`](SECURITY.md)
- Threat model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
- Production security checklist: [`docs/SECURITY_CHECKLIST.md`](docs/SECURITY_CHECKLIST.md)
- Known limits and constraints: [`docs/KNOWN_LIMITS.md`](docs/KNOWN_LIMITS.md)
- CI enforces format/lint/tests/publish dry-run on pushes and PRs
- Quick local baseline benchmark:

```bash
cargo run --release --example eval_benchmark -- 20000
```

## Production starter pack

- Standardized spec: [`SPEC.md`](SPEC.md)
- Operations runbook: [`docs/OPERATIONS.md`](docs/OPERATIONS.md)
- 30-minute integration path: [`docs/INTEGRATION_GUIDE.md`](docs/INTEGRATION_GUIDE.md)
- Conformance runner: `./scripts/conformance.sh`
- External interop runner: `./scripts/external_interop.sh` (requires endpoint env vars)
- Release gate runner: `./scripts/release_check.sh`

## Feature flags

| Flag | What it enables |
|---|---|
| *(none)* | Core evaluation pipeline, adapters, builders, file-backed state |
| `async` | `AsyncTrustStateStore` trait + async engine variants |
| `axum` | `DelegatedLayer` Tower middleware for axum |
| `client` | `DelegatedClient` for sending trust-validated outbound requests |
| `redis` | `RedisTrustStateStore` backed by Redis (async) |
| `tracing` | `tracing` spans on the evaluation hot path |
| `metrics` | `metrics` counters and histograms |
| `oidc-bridge` | `IdentityVerifier` trait for OIDC-based identity verification |

## Quickstart — server side (axum middleware)

```rust
use std::sync::Arc;
use delegated::{
    DelegatedLayerBuilder, InMemoryAsyncTrustState, JsonlFileAuditSink,
};

let trust_state = Arc::new(InMemoryAsyncTrustState::new());
let sink = Arc::new(JsonlFileAuditSink::new("audit.jsonl"));
let layer = DelegatedLayerBuilder::new(trust_state, sink)
    .with_max_body_bytes(1024 * 1024) // optional, default is 1 MiB
    .build();

let app = axum::Router::new()
    .route("/tools/call", axum::routing::post(my_handler))
    .layer(layer);
```

Every POST to `/tools/call` is evaluated before `my_handler` runs. Denied requests return 403 with `{allowed, stage, reason}` JSON; allowed requests pass through. Oversized request bodies return 413.

## Quickstart — client side

Build a `RequestEnvelope` with the issuance builders and attach it to outbound requests:

```rust
use delegated::{
    DelegatedClient,
    issuance::{AgentIdentityDocumentBuilder, DelegationTokenBuilder, RequestEnvelopeBuilder},
};
use ed25519_dalek::SigningKey;

let key = SigningKey::from_bytes(&secret_key_bytes);

let doc = AgentIdentityDocumentBuilder::new()
    .agent_id("agent:example:scheduler:v1")
    .owner_id("org:example")
    .issuer("https://trust.example.ai")
    .identity_type("spiffe")
    .subject("spiffe://example.ai/agents/scheduler")
    .key_id("key-2026-01")
    // Register an additional key for rotation:
    .additional_public_key("key-2026-02", &rotation_key.verifying_key())
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
    .expires_in(chrono::Duration::hours(1))
    .build_and_sign(&key)?;

let envelope = RequestEnvelopeBuilder::new()
    .identity_document(doc)
    .token(token)
    .audience("tool:google-calendar")
    .action("calendar.create_event")
    .build()?;

let client = DelegatedClient::new();
let resp = client.evaluate_http("https://api.example.com/trust", &envelope).await?;
if resp.is_allowed() {
    // proceed
}
```

## Standalone adapters (without axum)

Call the adapters directly in any async or sync context:

```rust
// HTTP (sync)
use delegated::{handle_http_json_request, JsonlFileAuditSink};
use chrono::Utc;

let sink = JsonlFileAuditSink::new("audit.jsonl");
let response = handle_http_json_request(&raw_body, Utc::now(), &sink);
// response.status_code, response.body["allowed"]

// MCP
use delegated::handle_mcp_jsonrpc_request;
let response = handle_mcp_jsonrpc_request(&raw_body, Utc::now(), &sink);

// A2A
use delegated::handle_a2a_request;
let response = handle_a2a_request(&raw_body, Utc::now(), &sink);
```

## Host context vs request runtime context

`runtime_context` in `RequestEnvelope` is caller-provided data used for request-specific checks (spend amount, target email/calendar, etc).

Security-sensitive trust signals (delegation depth, cognitive/reputation/risk assessments, extra approvals, clock leeway) are supplied by your infrastructure via `HostContext`/`HostContextProvider` and are never trusted from inbound request JSON.

## Trust state

**Sync** (suitable for single-process / CLI use):

```rust
use delegated::{InMemoryTrustState, FileBackedTrustState, TrustStateAdmin};
use std::sync::Arc;

// In-memory with interior mutability — share as Arc<InMemoryTrustState>
let state = Arc::new(InMemoryTrustState::new());
state.revoke_token("dlg_abc")?;
state.emergency_deny_agent("agent:bad")?;
state.revoke_tokens(&["dlg_1", "dlg_2", "dlg_3"])?;
state.clear_emergency_deny_list()?;
state.flush_expired_nonces(chrono::Utc::now())?;

// File-backed (advisory lock, CLI / single-process only)
let state = FileBackedTrustState::new(delegated::default_trust_state_path());
```

For convenience entry points that do not accept explicit state (`evaluate_request`, `evaluate_and_audit`, and default adapter wrappers), in-memory runtime state is now process-shared so nonce replay protection persists across calls in the same process.

**Async** (Redis for production):

```rust
#[cfg(feature = "redis")]
use delegated::RedisTrustStateStore;
let state = Arc::new(RedisTrustStateStore::connect("redis://127.0.0.1").await?);
// revoke_tokens uses a Redis pipeline; clear_emergency_deny_list uses SCAN+DEL
```

To enforce this in production, set `DELEGATED_REQUIRE_SHARED_BACKEND=1` (or `DELEGATED_ENV=production`).
When enabled, sync convenience runtime paths fail closed, and `DelegatedLayerBuilder` requires a shared async backend.

## Revocation and control plane

```rust
use delegated::{
    revoke_token_with_receipt, emergency_deny_agent, simulate_policy_with_host_context,
    HostContext, InMemoryTrustState
};

let state = InMemoryTrustState::new();
// Revoke with an auditable receipt
let op = revoke_token_with_receipt(
    &state, "req_123", "dlg_abc".to_string(), "user:operator",
    Some("compromised".to_string()), chrono::Utc::now(),
)?;
println!("receipt: {}", op.receipt.request_id);
```

`simulate_policy` runs **policy checks only** (no signature, lifetime, revocation, or binding stages).  
Use `simulate_policy_with_host_context` when you need simulation results that reflect trusted deployment signals (for example delegation depth).

## Trust pipeline

Every evaluation runs these stages in order, fail-closing at the first failure:

1. `normalize_request` — parse and contract-validate the request envelope
2. `validate_profile_compatibility` — SPIFFE / OIDC / Developer profile checks
3. `verify_signatures` — Ed25519 on identity document and delegation token
4. `validate_identity_document_lifetime` — expiry with configurable clock leeway
5. `enforce_revocation_and_redelegation` — revocation, emergency deny, nonce replay, delegation depth
6. `validate_token_lifetime` — token `issued_at` / `expires_at` window
7. `validate_token_binding` — `agent_id`, `delegator_id`, audience cross-check
8. `evaluate_policy` — allowed actions, max spend, calendar constraints, cognitive/reputation gates

## Custom policy

```rust
use delegated::{Policy, PolicyCheck, RequestEnvelope, HostContext};

struct MyPolicy;
impl Policy for MyPolicy {
    fn evaluate(&self, envelope: &RequestEnvelope, ctx: &HostContext) -> Vec<PolicyCheck> {
        vec![PolicyCheck {
            name: "my_check".to_string(),
            passed: envelope.agent_id.starts_with("agent:trusted:"),
            reason: "agent not in trusted namespace".to_string(),
        }]
    }
}

// Pass to evaluate_request_with_policy / evaluate_and_audit_with_policy
```

## CLI

```bash
cargo run --bin delegated-cli -- help

# Sign an identity document
delegated-cli sign-identity identity.json <base64url-private-key>

# Sign a delegation token
delegated-cli sign-token token.json <base64url-private-key>

# Verify a request envelope offline (uses durable CLI trust state path)
delegated-cli verify-request request.json

# Interactive grant approval
delegated-cli approve-grant-interactive proposal.json user:operator

# Revoke a token (persists to ~/.delegated/trust-state.json)
delegated-cli revoke-token req_123 dlg_abc user:operator --reason "manual revoke"
```

## Repository layout

```
src/
  engine.rs            — trust evaluation orchestration
  stages.rs            — individual evaluation stages
  policy.rs            — built-in policy checks
  revocation.rs        — TrustStateStore/Admin traits + InMemoryTrustState + FileBackedTrustState
  revocation_async.rs  — AsyncTrustStateStore/Admin + InMemoryAsyncTrustState
  revocation_redis.rs  — RedisTrustStateStore (feature: redis)
  issuance.rs          — DelegationTokenBuilder + AgentIdentityDocumentBuilder + RequestEnvelopeBuilder
  adapters/
    http.rs            — HTTP adapter
    mcp.rs             — MCP JSON-RPC adapter
    a2a.rs             — A2A adapter
    axum_layer.rs      — Tower Layer middleware (feature: axum)
    guard.rs           — rate limit + concurrency guard
  client.rs            — DelegatedClient (feature: client)
  audit.rs             — AuditSink trait + JsonlFileAuditSink
  discovery.rs         — DiscoveryService + JWKS handlers
  control_plane.rs     — revocation receipts + operational reports
  crypto.rs            — signing + verification primitives
tests/
  conformance.rs       — end-to-end allow/deny/replay/revocation
  interop_harness.rs   — cross-adapter and cross-profile parity
  reference_cli.rs     — CLI signing/verification/approval workflows
  integration_server.rs — real axum server + DelegatedClient round-trips
```

## Testing

```bash
# Core tests
cargo test

# Integration tests (requires axum + client features)
cargo test --features "axum,client" --test integration_server

# With all optional features
cargo test --features "async,axum,client,tracing,metrics"
```

## License

Licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
