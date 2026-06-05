//! Generator for signet reference test vectors.
//!
//! Prints a JSON manifest to stdout containing pre-signed `RequestEnvelope` fixtures
//! that any language's implementation can use to validate its signet evaluator.
//!
//! Usage:
//!   cargo run --example gen_vectors > tests/vectors/vectors.json
//!
//! The signing key is the Ed25519 key derived from the 32-byte seed 0x42 (repeated).
//! All vectors are evaluated at 2026-06-05T12:00:00Z.

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use signet::{
    issuance::{AgentIdentityDocumentBuilder, DelegationTokenBuilder, RequestEnvelopeBuilder},
    models::{AgentIdentityDocument, DelegationToken, RuntimeContext, TrustProfile},
};

// ---------------------------------------------------------------------------
// Fixed parameters
// ---------------------------------------------------------------------------

const SEED: [u8; 32] = [0x42u8; 32];
const AGENT_ID: &str = "agent:example:scheduler:v1";
const DELEGATOR_ID: &str = "user:jake-abendroth";
const OWNER_ID: &str = "org:example";
const ISSUER: &str = "https://trust.example.ai";
const KEY_ID: &str = "key-2026-01";
const AUDIENCE: &str = "tool:google-calendar";
const ACTION: &str = "calendar.create_event";
const EVALUATE_AT: &str = "2026-06-05T12:00:00Z";

fn key() -> SigningKey {
    SigningKey::from_bytes(&SEED)
}

fn ts(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(y, mo, d, h, mi, s)
        .single()
        .expect("valid timestamp")
}

fn token_issued_at() -> DateTime<Utc> {
    ts(2026, 6, 5, 11, 50, 0)
}
fn token_expires_at() -> DateTime<Utc> {
    ts(2026, 6, 5, 13, 0, 0)
}
fn identity_created_at() -> DateTime<Utc> {
    ts(2026, 6, 1, 0, 0, 0)
}
fn identity_expires_at() -> DateTime<Utc> {
    ts(2026, 6, 12, 0, 0, 0)
}

/// Returns the base64url-no-pad encoding of 64 zero bytes.
/// This is a syntactically valid Ed25519 signature encoding that will always
/// fail cryptographic verification.
fn bogus_sig() -> String {
    Base64UrlUnpadded::encode_string(&[0u8; 64])
}

// ---------------------------------------------------------------------------
// Builder helpers
// ---------------------------------------------------------------------------

fn build_identity(identity_type: &str, subject: &str) -> AgentIdentityDocument {
    AgentIdentityDocumentBuilder::new()
        .agent_id(AGENT_ID)
        .owner_id(OWNER_ID)
        .issuer(ISSUER)
        .identity_type(identity_type)
        .subject(subject)
        .key_id(KEY_ID)
        .supported_protocol("http")
        .supported_auth_method("delegation_token")
        .endpoint("http", "https://agents.example.ai/scheduler")
        .created_at(identity_created_at())
        .expires_at(identity_expires_at())
        .build_and_sign(&key())
        .expect("identity build_and_sign")
}

fn build_token(vector_id: &str) -> DelegationToken {
    DelegationTokenBuilder::new()
        .token_id(format!("dlg-{vector_id}"))
        .issuer(ISSUER)
        .agent_id(AGENT_ID)
        .delegator_id(DELEGATOR_ID)
        .owner_id(OWNER_ID)
        .audience(AUDIENCE)
        .allowed_action(ACTION)
        .key_id(KEY_ID)
        .nonce(format!("nonce-{vector_id}"))
        .issued_at(token_issued_at())
        .expires_at(token_expires_at())
        .build_and_sign(&key())
        .expect("token build_and_sign")
}

/// Build the standard developer-profile envelope as a `serde_json::Value`.
fn build_base_envelope(vector_id: &str) -> Value {
    let identity = build_identity("developer", AGENT_ID);
    let token = build_token(vector_id);
    let envelope = RequestEnvelopeBuilder::new()
        .request_id(vector_id)
        .profile(TrustProfile::Developer)
        .agent_id(AGENT_ID)
        .delegator_id(DELEGATOR_ID)
        .audience(AUDIENCE)
        .action(ACTION)
        .identity_document(identity)
        .token(token)
        .build()
        .expect("envelope build");
    serde_json::to_value(envelope).expect("serialize envelope")
}

fn make_vector(
    id: &str,
    description: &str,
    envelope: Value,
    allowed: bool,
    stage: &str,
    reason: &str,
) -> Value {
    json!({
        "id": id,
        "description": description,
        "evaluate_at": EVALUATE_AT,
        "envelope": envelope,
        "expected": {
            "allowed": allowed,
            "stage": stage,
            "reason": reason
        }
    })
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    let k = key();
    let pubkey_b64 = Base64UrlUnpadded::encode_string(&k.verifying_key().to_bytes());

    let mut vectors: Vec<Value> = Vec::new();

    // -----------------------------------------------------------------------
    // allow-basic — fully valid developer-profile request
    // -----------------------------------------------------------------------
    {
        let env = build_base_envelope("allow-basic");
        vectors.push(make_vector(
            "allow-basic",
            "Valid request; all stages pass",
            env,
            true,
            "evaluate_policy",
            "request authorized",
        ));
    }

    // -----------------------------------------------------------------------
    // allow-spiffe — valid request using the SPIFFE trust profile
    // -----------------------------------------------------------------------
    {
        let identity = build_identity("spiffe", "spiffe://example.ai/agents/scheduler");
        let token = build_token("allow-spiffe");
        let envelope = RequestEnvelopeBuilder::new()
            .request_id("allow-spiffe")
            .profile(TrustProfile::Spiffe)
            .agent_id(AGENT_ID)
            .delegator_id(DELEGATOR_ID)
            .audience(AUDIENCE)
            .action(ACTION)
            .identity_document(identity)
            .token(token)
            .build()
            .expect("envelope build");
        let env = serde_json::to_value(envelope).expect("serialize envelope");
        vectors.push(make_vector(
            "allow-spiffe",
            "Valid request using the SPIFFE trust profile; identity_type=spiffe, subject=spiffe://...",
            env,
            true,
            "evaluate_policy",
            "request authorized",
        ));
    }

    // -----------------------------------------------------------------------
    // deny-expired-token — token.expires_at is before evaluate_at
    // Must re-sign the token after changing the timestamps.
    // -----------------------------------------------------------------------
    {
        let identity = build_identity("developer", AGENT_ID);
        let token = DelegationTokenBuilder::new()
            .token_id("dlg-deny-expired-token")
            .issuer(ISSUER)
            .agent_id(AGENT_ID)
            .delegator_id(DELEGATOR_ID)
            .owner_id(OWNER_ID)
            .audience(AUDIENCE)
            .allowed_action(ACTION)
            .key_id(KEY_ID)
            .nonce("nonce-deny-expired-token")
            .issued_at(ts(2026, 6, 5, 10, 50, 0))
            .expires_at(ts(2026, 6, 5, 11, 0, 0)) // 1 hour before evaluate_at
            .build_and_sign(&k)
            .expect("token build_and_sign");
        let envelope = RequestEnvelopeBuilder::new()
            .request_id("deny-expired-token")
            .profile(TrustProfile::Developer)
            .agent_id(AGENT_ID)
            .delegator_id(DELEGATOR_ID)
            .audience(AUDIENCE)
            .action(ACTION)
            .identity_document(identity)
            .token(token)
            .build()
            .expect("envelope build");
        let env = serde_json::to_value(envelope).expect("serialize");
        vectors.push(make_vector(
            "deny-expired-token",
            "Token expires_at (2026-06-05T11:00:00Z) is before evaluate_at (2026-06-05T12:00:00Z); lifetime check fails",
            env,
            false,
            "validate_token_lifetime",
            "delegation token expired",
        ));
    }

    // -----------------------------------------------------------------------
    // deny-future-token — token.issued_at is after evaluate_at
    // Must re-sign the token after changing the timestamps.
    // -----------------------------------------------------------------------
    {
        let identity = build_identity("developer", AGENT_ID);
        let token = DelegationTokenBuilder::new()
            .token_id("dlg-deny-future-token")
            .issuer(ISSUER)
            .agent_id(AGENT_ID)
            .delegator_id(DELEGATOR_ID)
            .owner_id(OWNER_ID)
            .audience(AUDIENCE)
            .allowed_action(ACTION)
            .key_id(KEY_ID)
            .nonce("nonce-deny-future-token")
            .issued_at(ts(2026, 6, 5, 14, 0, 0)) // 2 hours after evaluate_at
            .expires_at(ts(2026, 6, 5, 15, 0, 0))
            .build_and_sign(&k)
            .expect("token build_and_sign");
        let envelope = RequestEnvelopeBuilder::new()
            .request_id("deny-future-token")
            .profile(TrustProfile::Developer)
            .agent_id(AGENT_ID)
            .delegator_id(DELEGATOR_ID)
            .audience(AUDIENCE)
            .action(ACTION)
            .identity_document(identity)
            .token(token)
            .build()
            .expect("envelope build");
        let env = serde_json::to_value(envelope).expect("serialize");
        vectors.push(make_vector(
            "deny-future-token",
            "Token issued_at (2026-06-05T14:00:00Z) is after evaluate_at (2026-06-05T12:00:00Z); token not yet active",
            env,
            false,
            "validate_token_lifetime",
            "delegation token not active yet",
        ));
    }

    // -----------------------------------------------------------------------
    // deny-expired-identity — identity_document.expires_at is before evaluate_at
    // Must re-sign the identity document after changing its expiry.
    // -----------------------------------------------------------------------
    {
        let identity = AgentIdentityDocumentBuilder::new()
            .agent_id(AGENT_ID)
            .owner_id(OWNER_ID)
            .issuer(ISSUER)
            .identity_type("developer")
            .subject(AGENT_ID)
            .key_id(KEY_ID)
            .supported_protocol("http")
            .supported_auth_method("delegation_token")
            .endpoint("http", "https://agents.example.ai/scheduler")
            .created_at(identity_created_at())
            .expires_at(ts(2026, 6, 5, 11, 0, 0)) // 1 hour before evaluate_at
            .build_and_sign(&k)
            .expect("identity build_and_sign");
        let token = build_token("deny-expired-identity");
        let envelope = RequestEnvelopeBuilder::new()
            .request_id("deny-expired-identity")
            .profile(TrustProfile::Developer)
            .agent_id(AGENT_ID)
            .delegator_id(DELEGATOR_ID)
            .audience(AUDIENCE)
            .action(ACTION)
            .identity_document(identity)
            .token(token)
            .build()
            .expect("envelope build");
        let env = serde_json::to_value(envelope).expect("serialize");
        vectors.push(make_vector(
            "deny-expired-identity",
            "Identity document expires_at (2026-06-05T11:00:00Z) is before evaluate_at; document lifetime check fails",
            env,
            false,
            "validate_identity_document_lifetime",
            "identity document expired",
        ));
    }

    // -----------------------------------------------------------------------
    // deny-bad-token-signature — valid envelope, then token signature replaced
    // with 64 zero bytes. Cryptographic verification fails.
    // -----------------------------------------------------------------------
    {
        let mut env = build_base_envelope("deny-bad-token-signature");
        env["delegation_token"]["signature"] = json!(bogus_sig());
        vectors.push(make_vector(
            "deny-bad-token-signature",
            "Token signature replaced with 64 zero bytes; Ed25519 verification fails",
            env,
            false,
            "verify_signatures",
            "delegation token signature verification failed for selected key_id",
        ));
    }

    // -----------------------------------------------------------------------
    // deny-bad-identity-signature — valid envelope, then identity signature
    // replaced with 64 zero bytes. Cryptographic verification fails.
    // -----------------------------------------------------------------------
    {
        let mut env = build_base_envelope("deny-bad-identity-signature");
        env["identity_document"]["signature"] = json!(bogus_sig());
        vectors.push(make_vector(
            "deny-bad-identity-signature",
            "Identity document signature replaced with 64 zero bytes; Ed25519 verification fails",
            env,
            false,
            "verify_signatures",
            "identity document signature verification failed for all keys",
        ));
    }

    // -----------------------------------------------------------------------
    // deny-wrong-action — envelope.action is not in token.allowed_actions
    // No re-signing needed: the envelope is not signed; only the token and
    // identity document carry signatures.
    // -----------------------------------------------------------------------
    {
        let mut env = build_base_envelope("deny-wrong-action");
        env["action"] = json!("calendar.delete_event");
        vectors.push(make_vector(
            "deny-wrong-action",
            "Requested action (calendar.delete_event) is not in token allowed_actions; policy check fails",
            env,
            false,
            "evaluate_policy",
            "requested action not in token allowed_actions",
        ));
    }

    // -----------------------------------------------------------------------
    // deny-binding-mismatch — envelope.delegator_id differs from
    // token.delegator_id. The token and identity signatures remain valid;
    // only the binding check at validate_token_binding detects the mismatch.
    //
    // Note: changing token.agent_id without also changing identity.agent_id
    // would be caught earlier at verify_signatures (which cross-checks
    // identity.agent_id == token.agent_id). The delegator_id field is the
    // clean way to exercise the validate_token_binding stage.
    // -----------------------------------------------------------------------
    {
        let mut env = build_base_envelope("deny-binding-mismatch");
        // Token carries delegator_id = "user:jake-abendroth"; envelope now disagrees.
        env["delegator_id"] = json!("user:other-user");
        vectors.push(make_vector(
            "deny-binding-mismatch",
            "Envelope delegator_id does not match token delegator_id; binding check fails",
            env,
            false,
            "validate_token_binding",
            "token delegator_id does not match request delegator_id",
        ));
    }

    // -----------------------------------------------------------------------
    // deny-unsupported-version — spec_version "99.0" on envelope and token.
    // Contract validation rejects the unknown version at normalize_request.
    // -----------------------------------------------------------------------
    {
        let mut env = build_base_envelope("deny-unsupported-version");
        env["spec_version"] = json!("99.0");
        env["delegation_token"]["spec_version"] = json!("99.0");
        vectors.push(make_vector(
            "deny-unsupported-version",
            "spec_version 99.0 is not in the supported versions list; normalize_request rejects it",
            env,
            false,
            "normalize_request",
            "specifies unsupported version",
        ));
    }

    // -----------------------------------------------------------------------
    // deny-malformed-envelope — delegation_token field omitted entirely.
    // Deserialization fails because the field is required.
    // -----------------------------------------------------------------------
    {
        let mut env = build_base_envelope("deny-malformed-envelope");
        if let Value::Object(ref mut map) = env {
            map.remove("delegation_token");
        }
        vectors.push(make_vector(
            "deny-malformed-envelope",
            "delegation_token field is missing; deserialization fails at normalize_request",
            env,
            false,
            "normalize_request",
            "request does not match contract",
        ));
    }

    // -----------------------------------------------------------------------
    // deny-spend-exceeded — token.max_spend = 100 USD, but
    // runtime_context.requested_spend = 200 USD. Policy check fails.
    // -----------------------------------------------------------------------
    {
        let identity = build_identity("developer", AGENT_ID);
        let token = DelegationTokenBuilder::new()
            .token_id("dlg-deny-spend-exceeded")
            .issuer(ISSUER)
            .agent_id(AGENT_ID)
            .delegator_id(DELEGATOR_ID)
            .owner_id(OWNER_ID)
            .audience(AUDIENCE)
            .allowed_action(ACTION)
            .key_id(KEY_ID)
            .nonce("nonce-deny-spend-exceeded")
            .issued_at(token_issued_at())
            .expires_at(token_expires_at())
            .max_spend(100, "USD")
            .build_and_sign(&k)
            .expect("token build_and_sign");
        let envelope = RequestEnvelopeBuilder::new()
            .request_id("deny-spend-exceeded")
            .profile(TrustProfile::Developer)
            .agent_id(AGENT_ID)
            .delegator_id(DELEGATOR_ID)
            .audience(AUDIENCE)
            .action(ACTION)
            .identity_document(identity)
            .token(token)
            .runtime_context(RuntimeContext {
                requested_spend: Some(200),
                spend_currency: Some("USD".to_string()),
                target_email: None,
                target_calendar_id: None,
            })
            .build()
            .expect("envelope build");
        let env = serde_json::to_value(envelope).expect("serialize");
        vectors.push(make_vector(
            "deny-spend-exceeded",
            "Requested spend (200 USD) exceeds token max_spend (100 USD); policy check fails",
            env,
            false,
            "evaluate_policy",
            "requested spend exceeds token max_spend",
        ));
    }

    // -----------------------------------------------------------------------
    // Build and print the manifest
    // -----------------------------------------------------------------------
    let manifest = json!({
        "signet_spec_version": "0.1",
        "vectors_version": "1",
        "description": "signet reference test vectors",
        "notes": "Evaluate each vector at the timestamp in evaluate_at using the provided signing key. Do not use wall-clock time.",
        "signing_key": {
            "algorithm": "Ed25519",
            "seed_hex": "4242424242424242424242424242424242424242424242424242424242424242",
            "public_key_b64url": pubkey_b64
        },
        "vectors": vectors
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&manifest).expect("serialize manifest")
    );
}
