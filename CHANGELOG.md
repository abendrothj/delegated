# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Hardening and automation

- Added GitHub Actions CI workflow for `fmt`, strict `clippy`, test matrix, and publish dry-run validation.
- Added `SECURITY.md` with vulnerability reporting and deployment hardening guidance.
- Added `examples/eval_benchmark.rs` for quick local evaluation throughput baselines.
- Added comprehensive threat model (`docs/THREAT_MODEL.md`) and mapped production security checklist (`docs/SECURITY_CHECKLIST.md`).
- Added explicit production-facing known limits document (`docs/KNOWN_LIMITS.md`).
- Fixed nonce retention logic in sync trust-state stores to prune by current time, preserving replay protection across mixed token expiries.
- Added regression coverage for mixed-expiry nonce replay in sync and async trust-state tests.
- Updated CLI `verify-request` to use durable file-backed trust state by default (matching CLI operational expectations).
- Updated docs to prefer `default_trust_state_path()` over literal `~` paths in trust-state examples.
- Enforced currency matching in `max_spend` policy checks (`runtime_context.spend_currency` must match token `max_spend.currency`).
- Fixed MCP adapter method validation (sync + async adapters now require JSON-RPC `method == "tools.call"`).
- Hardened axum oversized-body handling to classify limit errors by type (not string matching), and documented/guarded body-limit behavior.
- Hardened client response handling:
  - HTTP trust responses now require typed `allowed`/`stage`/`reason` fields (malformed payloads return `InvalidResponse`).
  - MCP requests now require `extra_params` to be a JSON object (invalid caller input is rejected).
  - `McpTrustResponse::is_allowed()` now requires semantic allow (`result.allowed == true`) in addition to absence of error.
- Made audit-log reads resilient to malformed JSONL lines (skip bad records, keep readable history).
- Reduced adapter-guard tuple-state growth by sweeping expired timestamp buckets and removing idle tuple keys.
- Reduced adapter-guard lock contention by moving guard state to sharded mutex maps.
- Added ordered audit-query reads with newest-first default (`AuditOrder`) for incident-response ergonomics.
- Added `simulate_policy_with_host_context` so control-plane policy simulation can use trusted host signals explicitly.
- Tightened issuance builder contracts:
  - `RequestEnvelopeBuilder::build` now requires `identity_document`.
  - `AgentIdentityDocumentBuilder::build_and_sign` now requires `supported_protocols`, `supported_auth_methods`, and `endpoints`.
- Tightened core trust schemas by disallowing unspecified extra fields in canonical request/token/identity/shared-claims structures.
- Clarified MCP/A2A wrapper schema intent as wire-helper envelopes (not raw adapter request contracts).
- Expanded CI coverage to a Linux/macOS/Windows core matrix and split release-only checks into a dedicated Ubuntu job.
- Simplified release check script to a single all-features test pass and improved operational dependency-review guidance.
- Expanded repository hygiene defaults in `.gitignore` for common local/editor/temp artifacts.
- Added property-based replay regression coverage (`proptest`) for randomized nonce sets in trust-state enforcement.
- Runtime convenience APIs now use process-shared in-memory trust state by default, preserving replay checks across calls in the same process.
- Added release provenance verification (`scripts/verify_release_provenance.sh`) and wired it into CI/release checks to catch tag/version drift.
- Added external interoperability harness (`tests/external_interop.rs`) and runner script (`scripts/external_interop.sh`) for validating third-party HTTP/MCP/A2A adapters.

### Production starter pack

- Added operations runbook (`docs/OPERATIONS.md`) for deployment, monitoring, and incident workflows.
- Added 30-minute integration guide (`docs/INTEGRATION_GUIDE.md`) for first production adoption.
- Added `scripts/conformance.sh` and `scripts/release_check.sh` for repeatable solo-team validation workflows.
- Added standardized implementation spec (`SPEC.md`) as the canonical normative behavior contract.

## [0.1.1] — 2026-06-04

### Metadata

- Added explicit crate documentation metadata (`documentation = "https://docs.rs/crate/delegated/latest"`) so crates.io resolves docs consistently.

## [0.1.0] — 2026-06-04

Initial public release.

### Core trust evaluation pipeline

- Fail-closed evaluation pipeline: normalize → profile compatibility → signature verification → identity document lifetime → revocation / nonce consumption → token lifetime → token binding → policy checks → audit.
- Ed25519 signature verification for both `AgentIdentityDocument` and `DelegationToken` using canonical JSON payloads.
- `TrustProfile` gating (Developer, OIDC, SPIFFE) with configurable leeway for clock skew.
- Spec versioning: `SUPPORTED_SPEC_VERSIONS` membership check for forward-compatible version negotiation.

### Protocol adapters

- **HTTP adapter** (`handle_http_json_request*`) — returns `{allowed, stage, reason}` JSON with 200/403/400/429/500 status codes.
- **MCP adapter** (`handle_mcp_jsonrpc_request*`) — validates `params._trust` in JSON-RPC 2.0 requests; returns JSON-RPC errors on deny.
- **A2A adapter** (`handle_a2a_request*`) — validates `trust_claims` in `A2aProtocolRequest` messages.
- **Axum middleware layer** (`DelegatedLayer`, `DelegatedLayerBuilder`) — Tower `Layer`/`Service` that reads the request body, runs the async trust pipeline, and either passes the request through or returns 403. Feature flag: `axum`.

### Issuance builders

- `DelegationTokenBuilder` — fluent builder with auto-generated `token_id` and `nonce`, relative expiry via `expires_in`, and `build_and_sign`.
- `AgentIdentityDocumentBuilder` — fluent builder with 7-day default expiry; `additional_public_key(kid, &VerifyingKey)` for key rotation (registers extra public keys alongside the primary signing key).
- `RequestEnvelopeBuilder` — assembles a `RequestEnvelope` from a signed identity document and token.

### Trust state

- `TrustStateStore` / `TrustStateAdmin` traits now take `&self` (interior mutability) — implementations can be shared as `Arc<dyn TrustStateStore>`.
- `InMemoryTrustState` — uses `Mutex<InMemoryTrustInner>` + `AtomicBool`; thread-safe and `Clone`-free sharing.
- `FileBackedTrustState` — advisory file-lock backed state for CLI and single-process deployments.
- Bulk admin operations: `revoke_tokens` (default: loop), `clear_emergency_deny_list`, `flush_expired_nonces` (default: no-op).
- `AsyncTrustStateStore` / `AsyncTrustStateAdmin` for async runtimes; `InMemoryAsyncTrustState` wraps `InMemoryTrustState` directly.
- Redis store (`RedisTrustStateStore`) with `SET NX EXAT` for atomic nonce consumption, pipeline-based `revoke_tokens`, and SCAN+DEL `clear_emergency_deny_list`. Feature flag: `redis`.

### Policy engine

- Built-in policy checks: `allowed_actions`, `delegation_depth`, `max_spend`, `calendar_constraint`, `email_domain_allowlist`, `cognitive_gate`, `reputation_risk_multiplier`.
- Custom policy via `Policy` trait; `DefaultPolicy` composes all built-in checks.
- `simulate_request_policy*` — dry-run evaluation that returns individual `PolicyCheck` results without consuming nonces or writing audit events.

### Audit

- `AuditSink` trait (`Send + Sync`) with `JsonlFileAuditSink` implementation.
- `AuditReader` + `AuditQuery` for reading and filtering audit events.

### Control plane

- `revoke_token_with_receipt` — revokes a token and issues a `ConsentReceipt`.
- `emergency_deny_agent` — blocks an agent ID globally.
- `build_operational_report` — summarizes audit events by stage and allow/deny counts.
- `record_approval_decision` — records a grant approval or denial with a callback payload.

### Discovery

- `DiscoveryService` with `handle_discovery_http_request` for `/.well-known/delegated-issuer` and JWKS endpoints.

### Client SDK

- `DelegatedClient` with `evaluate_http`, `evaluate_mcp`, and `evaluate_a2a` methods for sending trust-validated requests to services running the server-side adapters. Feature flag: `client`.

### Observability

- `tracing` instrumentation on the evaluation hot path. Feature flag: `tracing`.
- `metrics` counters (`delegated_requests_total`) and histograms (`delegated_evaluation_duration_seconds`). Feature flag: `metrics`.

### OIDC bridge

- `IdentityVerifier` trait for plugging in OIDC-based identity verification as a replacement for offline Ed25519 signature checks. Feature flag: `oidc-bridge`.
