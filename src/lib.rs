pub mod adapters;
pub mod audit;
pub mod contracts;
pub mod crypto;
pub mod engine;
pub mod models;
pub mod policy;
pub mod revocation;
pub mod stages;
pub mod wire;

pub use adapters::http::{
    HttpAdapterResponse, handle_http_json_request, handle_http_json_request_with_state,
};
pub use audit::{AuditSink, JsonlFileAuditSink};
pub use crypto::{
    SIGNATURE_ENCODING_BASE64URL_NO_PAD, SIGNATURE_WIRE_FORMAT, TOKEN_SIGNATURE_ALG_ED25519,
    sign_delegation_token, sign_identity_document,
};
pub use engine::{
    append_audit_event, evaluate_and_audit, evaluate_and_audit_with_state, evaluate_request,
    evaluate_request_with_state, simulate_request_policy,
};
pub use models::{AuditEvent, Decision, PolicyCheck, RequestEnvelope, Violation};
pub use revocation::InMemoryTrustState;
pub use wire::{
    A2aTrustEnvelope, McpTrustEnvelope, SharedTrustClaims, unwrap_a2a_claims, unwrap_mcp_claims,
    wrap_a2a_request, wrap_mcp_request,
};
