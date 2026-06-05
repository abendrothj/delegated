pub mod adapters;
pub mod audit;
pub mod contracts;
pub mod control_plane;
pub mod crypto;
pub mod delegation_ux;
pub mod discovery;
pub mod engine;
pub mod host_context;
pub mod issuance;
pub mod models;
pub mod policy;
pub mod policy_trait;
pub mod profiles;
pub mod revocation;
pub mod stages;
pub mod wire;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "async")]
pub mod engine_async;
#[cfg(feature = "async")]
pub mod revocation_async;
#[cfg(feature = "async")]
pub mod stages_async;

#[cfg(feature = "redis")]
pub mod revocation_redis;

#[cfg(feature = "oidc-bridge")]
pub mod identity_verifier;

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
pub use audit::{AuditOrder, AuditQuery, AuditReader, AuditSink, JsonlFileAuditSink};
pub use contracts::{SPEC_VERSION_CURRENT, SUPPORTED_SPEC_VERSIONS};
pub use control_plane::{
    ApprovalOperation, OperationalReport, PolicySimulationResult, RevocationOperation,
    build_operational_report, emergency_deny_agent, export_audit_events, record_approval_decision,
    revoke_token_with_receipt, simulate_policy, simulate_policy_with_host_context,
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
    append_audit_event, evaluate_and_audit, evaluate_and_audit_with_policy,
    evaluate_and_audit_with_runtime_config, evaluate_and_audit_with_state, evaluate_request,
    evaluate_request_with_policy, evaluate_request_with_runtime_config,
    evaluate_request_with_state, simulate_request_policy, simulate_request_policy_with_policy,
};
pub use host_context::{HostContextBuilder, HostContextProvider, StaticHostContextProvider};
pub use issuance::{
    AgentIdentityDocumentBuilder, DelegationTokenBuilder, IssuanceError, RequestEnvelopeBuilder,
};
pub use models::{
    AuditEvent, Decision, HostContext, PolicyCheck, RequestEnvelope, TrustProfile, Violation,
};
pub use policy::{
    check_allowed_action, check_calendar_constraint, check_cognitive_gate, check_delegation_depth,
    check_email_domain_allowlist, check_extra_constraints, check_max_spend,
    check_reputation_risk_multiplier,
};
pub use policy_trait::{DefaultPolicy, Policy};
pub use profiles::validate_profile_compatibility;
pub use revocation::{
    FileBackedTrustState, InMemoryTrustState, RuntimeTrustConfig, TrustStateAdmin,
    TrustStateBackend, TrustStateStore, default_trust_state_path,
};
pub use wire::{
    A2aTrustEnvelope, McpTrustEnvelope, SharedTrustClaims, unwrap_a2a_claims, unwrap_mcp_claims,
    wrap_a2a_request, wrap_mcp_request,
};

#[cfg(feature = "async")]
pub use adapters::a2a_async::{
    handle_a2a_request_with_async_state, handle_a2a_request_with_async_state_and_guard_config,
};
#[cfg(feature = "async")]
pub use adapters::http_async::{
    handle_http_json_request_with_async_state,
    handle_http_json_request_with_async_state_and_guard_config,
};
#[cfg(feature = "async")]
pub use adapters::mcp_async::{
    handle_mcp_jsonrpc_request_with_async_state,
    handle_mcp_jsonrpc_request_with_async_state_and_guard_config,
};
#[cfg(feature = "async")]
pub use engine_async::{
    evaluate_and_audit_with_async_state, evaluate_and_audit_with_async_state_and_policy,
    evaluate_request_with_async_state, evaluate_request_with_async_state_and_policy,
    simulate_request_policy_async,
};
#[cfg(feature = "async")]
pub use revocation_async::{AsyncTrustStateAdmin, AsyncTrustStateStore, InMemoryAsyncTrustState};

#[cfg(feature = "axum")]
pub use adapters::axum_layer::{
    AsyncHostContextProvider, StaticAsyncHostContextProvider, TrustLayer, TrustLayerBuilder,
};

#[cfg(feature = "client")]
pub use client::{
    A2aTrustResponse, ClientError, ClientErrorKind, HttpTrustResponse, McpTrustResponse,
    TrustClient,
};

#[cfg(feature = "redis")]
pub use revocation_redis::{RedisTrustStateStore, undeny_agent, unrevoke_token};

#[cfg(feature = "oidc-bridge")]
pub use engine::evaluate_request_with_verifier;
#[cfg(feature = "oidc-bridge")]
pub use identity_verifier::{IdentityVerifier, RequireExplicitVerifier};
