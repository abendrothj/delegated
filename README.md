# delegated

`delegated` is a Rust trust layer for agent-to-agent communication.  
It provides a protocol-agnostic trust pipeline, protocol-native adapters (HTTP/MCP/A2A), durable revocation/replay state, discovery/JWKS handlers, and CLI-first approval/revocation workflows.

## What this project is

This repository is a **reference implementation** of the trust model in [`DELEGATED_SPEC.md`](./DELEGATED_SPEC.md).

Core capabilities:

- Signature-backed identity + delegation verification (Ed25519)
- Fail-closed trust evaluation pipeline
- Revocation, emergency deny, nonce replay protection, delegation depth checks
- OIDC/SPIFFE/Developer profile compatibility checks
- HTTP, MCP JSON-RPC, and A2A adapter entrypoints
- Discovery metadata + JWKS + registry + endpoint resolution handlers
- CLI lifecycle for sign/verify/approve/revoke
- Conformance and interop test suites

## Project status

The implementation is production-oriented but still spec-driven (`v0.1` artifacts).  
Use this as a base for product integration and standardization work, not as a finalized internet standard.

## Repository layout

- `src/engine.rs` — trust evaluation pipeline orchestration
- `src/stages.rs` — normalization, signature, lifetime, binding, revocation stages
- `src/policy.rs` — policy + cognitive/reputation enforcement
- `src/revocation.rs` — durable/in-memory trust state + runtime config
- `src/adapters/` — HTTP, MCP, A2A adapters + adapter guardrails
- `src/discovery.rs` — hostable discovery/JWKS request handlers
- `src/control_plane.rs` — approval/revoke/report operations
- `src/bin/delegated-cli.rs` — CLI tools and lifecycle flows
- `schemas/` — JSON schemas for envelopes, tokens, identity, discovery docs
- `tests/` — conformance, interop, and CLI integration coverage

## Quickstart

### Prerequisites

- Rust toolchain (stable)

### Build and test

```bash
cargo test
```

### CLI help

```bash
cargo run --bin delegated-cli -- help
```

## Trust state and runtime defaults

By default, runtime entrypoints use **durable file-backed trust state**.

- Default path: `~/.delegated/trust-state.json`
- Override path: `DELEGATED_TRUST_STATE_PATH=/custom/path/trust-state.json`

In-memory state is still available for explicit test/dev usage via runtime config APIs.

## Trust pipeline (high-level)

`evaluate_request*` flows execute:

1. normalize + contract validation
2. profile compatibility
3. signature verification
4. identity + token lifetime checks
5. revocation / emergency deny / nonce replay / delegation-depth enforcement
6. token binding checks
7. policy evaluation
8. decision + audit event emission

## Protocol adapters

The core pipeline is protocol-agnostic; adapters translate wire payloads into `RequestEnvelope`:

- HTTP: `handle_http_json_request*`
- MCP: `handle_mcp_jsonrpc_request*`
- A2A: `handle_a2a_request*`

### Adapter guardrails

Adapter entrypoints enforce `(agent_id, delegator_id)` tuple limits:

- rate limit (default: `120` requests/minute)
- in-flight concurrency limit (default: `32`)

Tune using `AdapterGuardConfig` and `*_with_state_and_guard_config` adapter variants.

## Discovery and trust bootstrap handlers

`src/discovery.rs` provides framework-agnostic request handlers over `DiscoveryService`:

- `/.well-known/delegated-issuer`
- `/.well-known/jwks.json?agent_id=...`
- `/registry/{agent_id}`
- `/resolve/{agent_id}?protocol=...`

Use `handle_discovery_http_request` in your own HTTP server/router.

## CLI workflows

`delegated-cli` supports:

- `sign-identity`
- `sign-token`
- `verify-request`
- `approve-grant`
- `approve-grant-interactive`
- `revoke-token`

### Example: approve and revoke flow

```bash
# approve grant proposal
cargo run --bin delegated-cli -- \
  approve-grant ./proposal.json approve user:operator \
  --reason "approved for demo" \
  --token-id dlg_123 \
  --output ./approval-result.json

# revoke token (persists in durable trust state)
cargo run --bin delegated-cli -- \
  revoke-token req_123 dlg_123 user:operator \
  --reason "manual revoke" \
  --output ./revocation-result.json
```

## Schemas

The `schemas/` folder includes versioned artifacts for:

- request envelope
- delegation token
- agent identity document
- shared trust claims
- A2A/MCP trust envelopes
- issuer metadata
- JWKS

## Testing

Main suites:

- `tests/conformance.rs` — end-to-end allow/deny/tamper/replay/revocation
- `tests/interop_harness.rs` — parity across HTTP/MCP/A2A and profile variants
- `tests/reference_cli.rs` — CLI signing/verification/approval/revocation workflows

Run all tests:

```bash
cargo test
```

## Next integration step

Embed adapter/discovery handlers in your host service, register your identity + issuer metadata in `DiscoveryService`, and enforce trust on every agent/tool hop through the provided adapter entrypoints.
