# Threat Model

This document defines the security boundaries and attacker model for `signet`.

See also: [`KNOWN_LIMITS.md`](KNOWN_LIMITS.md)

## Security objectives

1. **Fail-closed authorization**: requests are denied on validation, policy, or backend trust-state errors.
2. **Delegation integrity**: only valid, signed identity documents and delegation tokens are accepted.
3. **Replay resistance**: previously consumed nonces are rejected.
4. **Operational containment**: emergency deny and revocation can block compromised actors quickly.
5. **Auditability**: each decision emits structured audit events.

## Trust boundaries

### Untrusted input

- inbound request JSON (`RequestEnvelope`, MCP/A2A wrappers)
- all fields in `runtime_context`

### Trusted control-plane / infrastructure input

- revocation and deny-list backend state
- `HostContext` signals (delegation depth, cognitive/reputation/risk signals, extra approvals, clock leeway)
- signing keys and identity/token issuance workflow

`HostContext` must come from trusted infrastructure; it is not sourced from request payloads.

## Assets

- signing private keys for identity and token issuance
- revocation backend state (token revocations, deny list, consumed nonces)
- audit trail integrity
- policy configuration and host trust signals

## Attacker capabilities considered

- sends arbitrary malformed/oversized JSON
- tampers with token or identity payloads/signatures
- replays previously valid delegated requests
- attempts audience/action/delegator/agent binding mismatches
- attempts to exploit backend outages for fail-open behavior

## Security controls mapped to code

1. **Contract validation / normalization**
   - `src/stages.rs::normalize_request`
   - `src/contracts.rs::validate_request_contract`
2. **Spec/kind/field-level validation**
   - `src/contracts.rs` (`validate_spec_version`, `validate_kind`, `validate_non_empty*`)
3. **Signature verification**
   - `src/stages.rs::verify_signatures`
   - `src/crypto.rs::verify_identity_document_signature`
   - `src/crypto.rs::verify_delegation_token_signature`
4. **Lifetime checks**
   - `src/stages.rs::validate_identity_document_lifetime`
   - `src/stages.rs::validate_token_lifetime`
5. **Binding checks**
   - `src/stages.rs::validate_token_binding`
6. **Replay/revocation/emergency deny**
   - `src/stages.rs::enforce_revocation_and_redelegation`
   - `src/stages_async.rs::enforce_revocation_and_redelegation_async`
   - backends: `src/revocation.rs`, `src/revocation_async.rs`, `src/revocation_redis.rs`
7. **Fail-closed backend behavior**
   - revocation-state errors become deny violations in `enforce_revocation_and_redelegation*`
8. **Policy enforcement**
   - `src/policy.rs` + `src/policy_trait.rs`
9. **Audit logging**
   - `src/engine.rs::evaluate_and_audit*`
   - `src/audit.rs::JsonlFileAuditSink`
10. **Axum request-size guard**
   - `src/adapters/axum_layer.rs::TrustLayerBuilder::with_max_body_bytes`
   - oversized body handling returns HTTP 413 in `TrustService::call`

## Non-goals / out of scope

- secure transport provisioning (TLS/mTLS termination)
- key custody/HSM/KMS architecture
- external identity attestation trust-chain correctness
- SOC2/ISO compliance controls
- host-side signal correctness beyond trust boundary assumptions

## Assumptions

1. Identity and token signing keys are protected and rotated.
2. `HostContext` values are provided by trusted systems.
3. Distributed deployments use shared trust state (Redis or equivalent), not local file state.
4. Audit sinks are durable enough for incident response requirements.

## Abuse and failure scenarios

### Revocation backend unavailable

Expected behavior: deny (fail-closed), not allow.

### Token replay

Expected behavior: nonce already consumed => deny.

### Oversized payload (axum)

Expected behavior: deny with HTTP 413 before trust pipeline evaluation.

### Signature tampering

Expected behavior: deny at `verify_signatures`.
