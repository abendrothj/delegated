pub mod adapters;
pub mod audit;
pub mod contracts;
pub mod control_plane;
pub mod crypto;
pub mod delegation_ux;
pub mod discovery;
pub mod engine;
pub mod models;
pub mod policy;
pub mod profiles;
pub mod revocation;
pub mod stages;
pub mod wire;

pub use adapters::a2a::{
    A2aProtocolRequest, A2aProtocolResponse, handle_a2a_request,
    handle_a2a_request_with_runtime_config, handle_a2a_request_with_state,
    handle_a2a_request_with_state_and_guard_config,
};
pub use adapters::guard::{
    AdapterGuardConfig, AdapterGuardLease, AdapterGuardViolation, enter_adapter_guard,
};
pub use adapters::http::{
    HttpAdapterResponse, handle_http_json_request, handle_http_json_request_with_runtime_config,
    handle_http_json_request_with_state, handle_http_json_request_with_state_and_guard_config,
};
pub use adapters::mcp::{
    McpJsonRpcResponse, handle_mcp_jsonrpc_request, handle_mcp_jsonrpc_request_with_runtime_config,
    handle_mcp_jsonrpc_request_with_state, handle_mcp_jsonrpc_request_with_state_and_guard_config,
};
pub use audit::{AuditQuery, AuditReader, AuditSink, JsonlFileAuditSink};
pub use control_plane::{
    ApprovalOperation, OperationalReport, PolicySimulationResult, RevocationOperation,
    build_operational_report, emergency_deny_agent, export_audit_events, record_approval_decision,
    revoke_token_with_receipt, simulate_policy,
};
pub use crypto::{
    SIGNATURE_ENCODING_BASE64URL_NO_PAD, SIGNATURE_WIRE_FORMAT, TOKEN_SIGNATURE_ALG_ED25519,
    sign_delegation_token, sign_identity_document,
};
pub use delegation_ux::{
    ApprovalCallbackPayload, ApprovalDecision, ConsentReceipt, ConsentStatus,
    DelegationGrantProposal, issue_consent_receipt, issue_revocation_receipt,
    render_cli_grant_summary, to_approval_callback,
};
pub use discovery::{
    DISCOVERY_ISSUER_PATH, DISCOVERY_JWKS_PATH, DISCOVERY_REGISTRY_PREFIX,
    DISCOVERY_RESOLVE_PREFIX, DiscoveryHttpRequest, DiscoveryHttpResponse, DiscoveryService,
    IssuerMetadata, JwkRecord, JwksDocument, build_jwks_document, handle_discovery_http_request,
};
pub use engine::{
    append_audit_event, evaluate_and_audit, evaluate_and_audit_with_runtime_config,
    evaluate_and_audit_with_state, evaluate_request, evaluate_request_with_runtime_config,
    evaluate_request_with_state, simulate_request_policy,
};
pub use models::{
    AuditEvent, Decision, HostContext, PolicyCheck, RequestEnvelope, TrustProfile, Violation,
};
pub use profiles::validate_profile_compatibility;
pub use revocation::{
    FileBackedTrustState, InMemoryTrustState, RuntimeTrustConfig, TrustStateAdmin,
    TrustStateBackend, TrustStateStore, default_trust_state_path,
};
pub use wire::{
    A2aTrustEnvelope, McpTrustEnvelope, SharedTrustClaims, unwrap_a2a_claims, unwrap_mcp_claims,
    wrap_a2a_request, wrap_mcp_request,
};
