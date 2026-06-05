# DELEGATED SPECIFICATION (Standardized)

**Status:** Active  
**Target:** `delegated` crate  
**Spec version:** `0.1`

This document defines the normative behavior contract for `delegated`.
Keywords **MUST**, **SHOULD**, and **MAY** are used as defined in RFC 2119.

## 1. Scope

`delegated` is a fail-closed trust-evaluation layer for agent requests.  
It standardizes:

1. Canonical request and trust objects
2. Evaluation stage ordering
3. Signature, lifetime, binding, and replay enforcement
4. Adapter-level request/response behavior
5. Audit event requirements

## 2. Canonical Objects

## 2.1 RequestEnvelope

An implementation MUST accept and evaluate a canonical envelope with:

- `spec_version`
- `kind`
- `agent_id`
- `delegator_id`
- `audience`
- `action`
- `delegation_token`

`identity_document` is required by issuance builders in this implementation profile.

## 2.2 DelegationToken

A valid token MUST include:

- issuer and subject binding fields (`issuer`, `agent_id`, `delegator_id`, `owner_id`)
- authorization fields (`audience[]`, `allowed_actions[]`)
- lifecycle fields (`issued_at`, `expires_at`, `nonce`, `token_id`)
- signature fields (`key_id`, `signature_alg`, `signature`)

`signature_alg` MUST be `Ed25519`.

## 2.3 AgentIdentityDocument

A valid identity document MUST include:

- identity metadata (`agent_id`, `owner_id`, `issuer`, `identity_type`, `subject`)
- key material (`public_keys[]`)
- compatibility metadata (`supported_protocols[]`, `supported_auth_methods[]`)
- endpoint metadata (`endpoints[]`)
- lifecycle (`created_at`, `expires_at`)
- `signature`

## 3. Cryptographic Rules

1. Implementations MUST verify Ed25519 signatures for identity documents and delegation tokens.
2. Verification MUST operate on canonicalized payloads with deterministic key ordering.
3. Signature verification failure MUST deny the request.

## 4. Evaluation Pipeline

The following stage order is REQUIRED:

1. `normalize_request`
2. `validate_profile_compatibility`
3. `verify_signatures`
4. `validate_identity_document_lifetime`
5. `enforce_revocation_and_redelegation`
6. `validate_token_lifetime`
7. `validate_token_binding`
8. `evaluate_policy`

Evaluation MUST fail closed at first failure.

## 5. Replay, Revocation, and Deny Controls

1. Token revocation checks MUST deny revoked tokens.
2. Emergency deny-list checks MUST deny blocked agents.
3. Nonce consumption MUST block replay.
4. Trust-state backend errors MUST fail closed.

For convenience APIs using default in-memory runtime state, replay persistence is process-shared in this implementation profile.

## 6. Profile Rules

## 6.1 Developer

No profile-only transport constraints; all standard verification/policy stages still apply.

## 6.2 OIDC

MUST enforce:

- `identity_type == "oidc"`
- HTTPS issuer
- non-empty subject
- `supported_auth_methods` contains `delegation_token`

## 6.3 SPIFFE

MUST enforce:

- `identity_type == "spiffe"`
- `subject` starts with `spiffe://`
- `supported_auth_methods` contains `delegation_token`
- at least one supported protocol in `http|mcp|a2a`

## 7. Adapter Semantics

## 7.1 HTTP Adapter

Response behavior:

- `200` allow
- `403` deny
- `400` malformed request
- `429` adapter guard throttle
- `500` internal audit-sink failure

## 7.2 MCP Adapter

1. Request MUST be JSON-RPC `2.0`.
2. `method` MUST be `tools.call` for trust-evaluated requests.
3. Claims MUST be present in `params._trust`.
4. Denials MUST be represented as JSON-RPC errors with trust context.

## 7.3 A2A Adapter

Trust claims MUST be carried in `A2aProtocolRequest.trust_claims`, with protocol-native allow/deny response.

## 8. Policy Simulation

`simulate_request_policy*` and control-plane policy simulation endpoints are policy-only tools.
They MUST NOT consume nonce state and MUST NOT write audit events.
They do NOT execute full signature/lifetime/revocation/binding stages.

## 9. Audit Requirements

Every evaluated request MUST emit an audit decision event including:

- timestamp (`occurred_at`)
- decision (`allowed`, `stage`, `reason`)
- request correlation (`request_id` when present)
- principal/action fields (`agent_id`, `delegator_id`, `audience`, `action`, `token_id`)

## 10. Conformance

An implementation is conformant to this spec profile if it:

1. Enforces the stage ordering in Section 4
2. Fails closed on trust-state backend errors
3. Enforces Ed25519 signature validation as specified
4. Enforces binding checks (`agent_id`, `delegator_id`, `audience`)
5. Blocks nonce replay
6. Emits audit events per Section 9

Repository conformance references:

- `tests/conformance.rs`
- `tests/interop_harness.rs`
- `tests/default_runtime_state.rs`
- `tests/external_interop.rs` (when external endpoints are configured)
