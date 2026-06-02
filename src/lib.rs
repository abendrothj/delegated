pub mod adapters;
pub mod audit;
pub mod contracts;
pub mod crypto;
pub mod engine;
pub mod models;
pub mod policy;
pub mod stages;

pub use adapters::http::{HttpAdapterResponse, handle_http_json_request};
pub use audit::{AuditSink, JsonlFileAuditSink};
pub use crypto::{
    SIGNATURE_ENCODING_BASE64URL_NO_PAD, SIGNATURE_WIRE_FORMAT, TOKEN_SIGNATURE_ALG_ED25519,
    sign_delegation_token, sign_identity_document,
};
pub use engine::{
    append_audit_event, evaluate_and_audit, evaluate_request, simulate_request_policy,
};
pub use models::{AuditEvent, Decision, PolicyCheck, RequestEnvelope, Violation};
