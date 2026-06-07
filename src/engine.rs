use crate::audit::{AuditSink, JsonlFileAuditSink, write_audit_event};
use crate::models::{AuditEvent, Decision, HostContext, PolicyCheck, RequestEnvelope, Violation};
use crate::policy_trait::{DefaultPolicy, Policy};
use crate::profiles::validate_profile_compatibility;
use crate::revocation::{
    RuntimeTrustConfig, SHARED_BACKEND_REQUIRED_REASON, TrustStateStore,
    require_shared_backend_in_production, trust_state_from_runtime_config,
};
use crate::stages::{
    enforce_revocation_and_redelegation, normalize_request, validate_identity_document_lifetime,
    validate_token_binding, validate_token_lifetime, verify_signatures,
};
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use std::io;
use std::path::Path;

pub fn evaluate_request(raw_request: &Value, now: DateTime<Utc>) -> (Decision, AuditEvent) {
    evaluate_request_with_runtime_config(raw_request, now, &RuntimeTrustConfig::default())
}

pub fn evaluate_request_with_runtime_config(
    raw_request: &Value,
    now: DateTime<Utc>,
    runtime_config: &RuntimeTrustConfig,
) -> (Decision, AuditEvent) {
    if require_shared_backend_in_production() {
        let violation = Violation::new("runtime_config", SHARED_BACKEND_REQUIRED_REASON);
        let decision = Decision::deny(violation.stage, violation.reason.clone());
        let event = from_raw(raw_request, &violation, now);
        return (decision, event);
    }
    let trust_state = trust_state_from_runtime_config(runtime_config);
    evaluate_request_with_state(
        raw_request,
        now,
        trust_state.as_ref(),
        &HostContext::default(),
    )
}

pub fn evaluate_request_with_state(
    raw_request: &Value,
    now: DateTime<Utc>,
    trust_state: &dyn TrustStateStore,
    host_context: &HostContext,
) -> (Decision, AuditEvent) {
    evaluate_request_with_policy(raw_request, now, trust_state, host_context, &DefaultPolicy)
}

#[cfg_attr(
    feature = "tracing",
    tracing::instrument(skip_all, fields(
        agent_id = %raw_request.get("agent_id").and_then(|v| v.as_str()).unwrap_or(""),
        action   = %raw_request.get("action").and_then(|v| v.as_str()).unwrap_or(""),
    ))
)]
pub fn evaluate_request_with_policy(
    raw_request: &Value,
    now: DateTime<Utc>,
    trust_state: &dyn TrustStateStore,
    host_context: &HostContext,
    policy: &dyn Policy,
) -> (Decision, AuditEvent) {
    #[cfg(feature = "metrics")]
    let _eval_start = std::time::Instant::now();

    let leeway = Duration::seconds(host_context.clock_leeway_secs as i64);

    let result = normalize_request(raw_request)
        .map(|envelope| apply_action_aliases(envelope, host_context))
        .and_then(validate_profile_compatibility)
        .and_then(verify_signatures)
        .and_then(|envelope| validate_identity_document_lifetime(envelope, now, leeway))
        .and_then(|envelope| {
            enforce_revocation_and_redelegation(envelope, trust_state, host_context)
        })
        .and_then(|envelope| validate_token_lifetime(envelope, now, leeway))
        .and_then(validate_token_binding)
        .and_then(|envelope| apply_policy_checks(envelope, host_context, policy));

    match result {
        Ok(envelope) => {
            let decision = Decision::allow("evaluate_policy", "request authorized");
            #[cfg(feature = "tracing")]
            tracing::info!(
                allowed = true,
                stage = "evaluate_policy",
                "trust decision: allowed"
            );
            #[cfg(feature = "metrics")]
            {
                metrics::counter!("signet_requests_total", "allowed" => "true").increment(1);
                metrics::histogram!("signet_evaluation_duration_seconds")
                    .record(_eval_start.elapsed().as_secs_f64());
            }
            let event = from_envelope(envelope, &decision, now);
            (decision, event)
        }
        Err(violation) => {
            #[cfg(feature = "tracing")]
            tracing::info!(
                allowed = false,
                stage = %violation.stage,
                reason = %violation.reason,
                "trust decision: denied"
            );
            #[cfg(feature = "metrics")]
            {
                metrics::counter!(
                    "signet_requests_total",
                    "allowed" => "false",
                    "stage" => violation.stage
                )
                .increment(1);
                metrics::histogram!("signet_evaluation_duration_seconds")
                    .record(_eval_start.elapsed().as_secs_f64());
            }
            let decision = Decision::deny(violation.stage, violation.reason.clone());
            let event = from_raw(raw_request, &violation, now);
            (decision, event)
        }
    }
}

#[cfg(feature = "oidc-bridge")]
pub fn evaluate_request_with_verifier(
    raw_request: &Value,
    now: DateTime<Utc>,
    trust_state: &dyn TrustStateStore,
    host_context: &HostContext,
    verifier: Option<&dyn crate::identity_verifier::IdentityVerifier>,
    policy: &dyn Policy,
) -> (Decision, AuditEvent) {
    use crate::stages::verify_signatures_with_verifier;

    let leeway = Duration::seconds(host_context.clock_leeway_secs as i64);

    let result = normalize_request(raw_request)
        .map(|envelope| apply_action_aliases(envelope, host_context))
        .and_then(validate_profile_compatibility)
        .and_then(|envelope| verify_signatures_with_verifier(envelope, verifier))
        .and_then(|envelope| validate_identity_document_lifetime(envelope, now, leeway))
        .and_then(|envelope| {
            enforce_revocation_and_redelegation(envelope, trust_state, host_context)
        })
        .and_then(|envelope| validate_token_lifetime(envelope, now, leeway))
        .and_then(validate_token_binding)
        .and_then(|envelope| apply_policy_checks(envelope, host_context, policy));

    match result {
        Ok(envelope) => {
            let decision = Decision::allow("evaluate_policy", "request authorized");
            let event = from_envelope(envelope, &decision, now);
            (decision, event)
        }
        Err(violation) => {
            let decision = Decision::deny(violation.stage, violation.reason.clone());
            let event = from_raw(raw_request, &violation, now);
            (decision, event)
        }
    }
}

/// Runs only policy checks against the parsed request envelope.
///
/// # Security — does not verify signatures, lifetimes, or revocation
///
/// This function **skips** the full trust evaluation pipeline. The following are
/// **not** performed:
/// - Ed25519 signature verification on the identity document or delegation token
/// - Token and identity document lifetime window checks
/// - Revocation store, emergency deny list, and nonce replay protection
///
/// It is intended for policy preview, configuration testing, and local development.
/// **Never use it as a production security gate.** For enforcement, use
/// [`evaluate_request_with_state`] or the axum [`TrustLayer`].
pub fn simulate_request_policy(
    raw_request: &Value,
    host_context: &HostContext,
) -> Result<Vec<PolicyCheck>, Violation> {
    simulate_request_policy_with_policy(raw_request, host_context, &DefaultPolicy)
}

/// Runs only the supplied [`Policy`] against the parsed request envelope.
///
/// # Security — does not verify signatures, lifetimes, or revocation
///
/// Same caveats as [`simulate_request_policy`]: signatures, lifetimes, and revocation
/// are **not** checked. For production enforcement use [`evaluate_request_with_policy`].
pub fn simulate_request_policy_with_policy(
    raw_request: &Value,
    host_context: &HostContext,
    policy: &dyn Policy,
) -> Result<Vec<PolicyCheck>, Violation> {
    let envelope = normalize_request(raw_request)?;
    Ok(policy.evaluate(&envelope, host_context))
}

pub fn append_audit_event(path: impl AsRef<Path>, event: &AuditEvent) -> io::Result<()> {
    let sink = JsonlFileAuditSink::new(path.as_ref().to_path_buf());
    write_audit_event(&sink, event)
}

pub fn evaluate_and_audit(
    raw_request: &Value,
    now: DateTime<Utc>,
    sink: &dyn AuditSink,
) -> io::Result<Decision> {
    evaluate_and_audit_with_runtime_config(raw_request, now, sink, &RuntimeTrustConfig::default())
}

pub fn evaluate_and_audit_with_runtime_config(
    raw_request: &Value,
    now: DateTime<Utc>,
    sink: &dyn AuditSink,
    runtime_config: &RuntimeTrustConfig,
) -> io::Result<Decision> {
    if require_shared_backend_in_production() {
        let violation = Violation::new("runtime_config", SHARED_BACKEND_REQUIRED_REASON);
        let decision = Decision::deny(violation.stage, violation.reason.clone());
        let event = from_raw(raw_request, &violation, now);
        write_audit_event(sink, &event)?;
        return Ok(decision);
    }
    let trust_state = trust_state_from_runtime_config(runtime_config);
    evaluate_and_audit_with_state(
        raw_request,
        now,
        sink,
        trust_state.as_ref(),
        &HostContext::default(),
    )
}

pub fn evaluate_and_audit_with_state(
    raw_request: &Value,
    now: DateTime<Utc>,
    sink: &dyn AuditSink,
    trust_state: &dyn TrustStateStore,
    host_context: &HostContext,
) -> io::Result<Decision> {
    evaluate_and_audit_with_policy(
        raw_request,
        now,
        sink,
        trust_state,
        host_context,
        &DefaultPolicy,
    )
}

pub fn evaluate_and_audit_with_policy(
    raw_request: &Value,
    now: DateTime<Utc>,
    sink: &dyn AuditSink,
    trust_state: &dyn TrustStateStore,
    host_context: &HostContext,
    policy: &dyn Policy,
) -> io::Result<Decision> {
    let (decision, event) =
        evaluate_request_with_policy(raw_request, now, trust_state, host_context, policy);
    write_audit_event(sink, &event)?;
    Ok(decision)
}

pub(crate) fn apply_policy_checks(
    envelope: RequestEnvelope,
    host_context: &HostContext,
    policy: &dyn Policy,
) -> Result<RequestEnvelope, Violation> {
    let checks = policy.evaluate(&envelope, host_context);
    if let Some(failure) = checks.iter().find(|c| !c.passed) {
        return Err(Violation::new("evaluate_policy", failure.reason.clone()));
    }
    Ok(envelope)
}

pub(crate) fn from_envelope(
    envelope: RequestEnvelope,
    decision: &Decision,
    now: DateTime<Utc>,
) -> AuditEvent {
    AuditEvent {
        occurred_at: now,
        allowed: decision.allowed,
        stage: decision.stage.clone(),
        reason: decision.reason.clone(),
        request_id: envelope.request_id,
        agent_id: Some(envelope.agent_id),
        delegator_id: Some(envelope.delegator_id),
        audience: Some(envelope.audience),
        action: Some(envelope.action),
        token_id: Some(envelope.token.token_id),
    }
}

pub(crate) fn from_raw(
    raw_request: &Value,
    violation: &Violation,
    now: DateTime<Utc>,
) -> AuditEvent {
    let request_id = extract_string(raw_request, &["request_id"]);
    let agent_id = extract_string(raw_request, &["agent_id"]);
    let delegator_id = extract_string(raw_request, &["delegator_id"]);
    let audience = extract_string(raw_request, &["audience"]);
    let action = extract_string(raw_request, &["action"]);
    let token_id = extract_string(raw_request, &["delegation_token", "token_id"]);

    AuditEvent {
        occurred_at: now,
        allowed: false,
        stage: violation.stage.to_string(),
        reason: violation.reason.clone(),
        request_id,
        agent_id,
        delegator_id,
        audience,
        action,
        token_id,
    }
}

/// Translates `envelope.action` to its canonical form using the host-side alias
/// map. Tokens always carry canonical action names; this lets the receiver
/// normalize whatever the caller sends without reissuing tokens.
pub(crate) fn apply_action_aliases(
    mut envelope: RequestEnvelope,
    host_context: &HostContext,
) -> RequestEnvelope {
    if let Some(canonical) = host_context.action_aliases.get(&envelope.action) {
        envelope.action = canonical.clone();
    }
    envelope
}

fn extract_string(root: &Value, path: &[&str]) -> Option<String> {
    let mut cursor = root;
    for key in path {
        cursor = cursor.get(*key)?;
    }
    let value = cursor.as_str()?.trim();
    if value.is_empty() {
        return None;
    }
    Some(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        TOKEN_SIGNATURE_ALG_ED25519, sign_delegation_token, sign_identity_document,
    };
    use crate::models::{
        AgentEndpoint, AgentIdentityDocument, DelegationToken, PublicKeyRecord, RequestEnvelope,
        RuntimeContext, TrustProfile,
    };
    use crate::revocation::InMemoryTrustState;
    use base64ct::{Base64UrlUnpadded, Encoding};
    use chrono::TimeZone;
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};

    static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 1, 20, 20, 0)
            .single()
            .expect("valid test timestamp")
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn unique_id() -> String {
        let counter = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_nanos();
        format!("{counter}_{nanos}")
    }

    fn valid_request() -> Value {
        let unique_id = unique_id();
        let key = signing_key();
        let mut identity_document = AgentIdentityDocument {
            spec_version: "0.1".to_string(),
            kind: "AgentIdentityDocument".to_string(),
            agent_id: "agent:example:scheduler:v1".to_string(),
            display_name: Some("example Scheduler Agent".to_string()),
            owner_id: "org:example".to_string(),
            issuer: "https://trust.example.ai".to_string(),
            identity_type: "spiffe".to_string(),
            subject: "spiffe://example.ai/agents/scheduler".to_string(),
            public_keys: vec![PublicKeyRecord {
                kid: "key-2026-01".to_string(),
                kty: "OKP".to_string(),
                crv: Some(TOKEN_SIGNATURE_ALG_ED25519.to_string()),
                x: Some(Base64UrlUnpadded::encode_string(
                    &key.verifying_key().to_bytes(),
                )),
            }],
            supported_protocols: vec!["http".to_string()],
            supported_auth_methods: vec!["delegation_token".to_string()],
            capabilities: None,
            endpoints: vec![AgentEndpoint {
                protocol: "http".to_string(),
                url: "https://agents.example.ai/scheduler".to_string(),
            }],
            attestation: None,
            created_at: Utc
                .with_ymd_and_hms(2026, 6, 1, 20, 0, 0)
                .single()
                .expect("valid timestamp"),
            expires_at: Utc
                .with_ymd_and_hms(2026, 6, 8, 20, 0, 0)
                .single()
                .expect("valid timestamp"),
            signature: String::new(),
        };
        identity_document.signature =
            sign_identity_document(&identity_document, &key).expect("identity signing should work");

        let mut token = DelegationToken {
            spec_version: "0.1".to_string(),
            kind: "DelegationToken".to_string(),
            token_id: format!("dlg_01J0EXAMPLE_{unique_id}"),
            issuer: "https://trust.example.ai".to_string(),
            agent_id: "agent:example:scheduler:v1".to_string(),
            delegator_id: "user:jake-abendroth".to_string(),
            owner_id: "org:example".to_string(),
            audience: vec!["tool:google-calendar".to_string(), "tool:gmail".to_string()],
            allowed_actions: vec![
                "calendar.create_event".to_string(),
                "calendar.read_availability".to_string(),
                "gmail.send_message".to_string(),
            ],
            resource_constraints: None,
            max_spend: None,
            max_delegation_depth: None,
            issued_at: Utc
                .with_ymd_and_hms(2026, 6, 1, 20, 10, 0)
                .single()
                .expect("valid timestamp"),
            expires_at: Utc
                .with_ymd_and_hms(2026, 6, 1, 20, 40, 0)
                .single()
                .expect("valid timestamp"),
            intent: Some("schedule_demo_and_send_confirmation".to_string()),
            nonce: format!("random-nonce-{unique_id}"),
            key_id: "key-2026-01".to_string(),
            signature_alg: TOKEN_SIGNATURE_ALG_ED25519.to_string(),
            signature: String::new(),
        };
        token.signature =
            sign_delegation_token(&token, &key).expect("delegation signing should work");

        let envelope = RequestEnvelope {
            spec_version: "0.1".to_string(),
            kind: "TrustRequestEnvelope".to_string(),
            request_id: Some(format!("req_{unique_id}")),
            profile: TrustProfile::Developer,
            agent_id: "agent:example:scheduler:v1".to_string(),
            delegator_id: "user:jake-abendroth".to_string(),
            audience: "tool:google-calendar".to_string(),
            action: "calendar.create_event".to_string(),
            resource: None,
            runtime_context: RuntimeContext::default(),
            identity_document: Some(identity_document),
            token,
        };

        serde_json::to_value(envelope).expect("request serialization should work")
    }

    fn resign_token(request: &mut Value) {
        let key = signing_key();
        let mut token: DelegationToken =
            serde_json::from_value(request["delegation_token"].clone())
                .expect("token should parse");
        token.signature = sign_delegation_token(&token, &key).expect("token resign should work");
        request["delegation_token"] = serde_json::to_value(token).expect("token serialization");
    }

    fn resign_identity_document(request: &mut Value) {
        let key = signing_key();
        let mut identity: AgentIdentityDocument =
            serde_json::from_value(request["identity_document"].clone())
                .expect("identity document should parse");
        identity.signature =
            sign_identity_document(&identity, &key).expect("identity resign should work");
        request["identity_document"] =
            serde_json::to_value(identity).expect("identity serialization should work");
    }

    #[test]
    fn allows_valid_request() {
        let (decision, event) = evaluate_request(&valid_request(), now());
        assert!(decision.allowed, "unexpected deny: {}", decision.reason);
        assert_eq!(decision.stage, "evaluate_policy");
        assert!(event.allowed);
        let token_id = event
            .token_id
            .as_deref()
            .expect("token id should be present");
        assert!(token_id.starts_with("dlg_01J0EXAMPLE_"));
    }

    #[test]
    fn denies_when_action_not_allowed() {
        let mut request = valid_request();
        request["action"] = Value::String("calendar.delete_event".to_string());

        let (decision, event) = evaluate_request(&request, now());
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "evaluate_policy");
        assert!(!event.allowed);
    }

    #[test]
    fn action_alias_translates_inbound_name_to_canonical() {
        // Token allows "calendar.create_event"; caller sends "GoogleCalendarCreate".
        let mut request = valid_request();
        request["action"] = serde_json::Value::String("GoogleCalendarCreate".to_string());

        let state = InMemoryTrustState::new();
        let host_context = crate::host_context::HostContextBuilder::new()
            .action_alias("GoogleCalendarCreate", "calendar.create_event")
            .build();
        let (decision, _) = evaluate_request_with_state(&request, now(), &state, &host_context);
        assert!(
            decision.allowed,
            "alias should translate to canonical action: {}",
            decision.reason
        );
    }

    #[test]
    fn action_alias_missing_still_denies_unknown_action() {
        let mut request = valid_request();
        request["action"] = serde_json::Value::String("UnknownAction".to_string());

        let state = InMemoryTrustState::new();
        // Alias map has no entry for "UnknownAction".
        let host_context = crate::host_context::HostContextBuilder::new()
            .action_alias("GoogleCalendarCreate", "calendar.create_event")
            .build();
        let (decision, _) = evaluate_request_with_state(&request, now(), &state, &host_context);
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "evaluate_policy");
    }

    #[test]
    fn denies_when_token_expired() {
        let mut request = valid_request();
        request["delegation_token"]["expires_at"] =
            Value::String("2026-06-01T20:15:00Z".to_string());
        resign_token(&mut request);

        let (decision, _event) = evaluate_request(&request, now());
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "validate_token_lifetime");
    }

    #[test]
    fn denies_when_identity_document_expired() {
        let mut request = valid_request();
        request["identity_document"]["expires_at"] =
            Value::String("2026-06-01T20:10:00Z".to_string());
        resign_identity_document(&mut request);
        let (decision, _event) = evaluate_request(&request, now());
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "validate_identity_document_lifetime");
    }

    #[test]
    fn denies_when_binding_mismatch() {
        let mut request = valid_request();
        request["delegator_id"] = Value::String("user:someone-else".to_string());

        let (decision, _event) = evaluate_request(&request, now());
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "validate_token_binding");
    }

    #[test]
    fn denies_on_malformed_request() {
        let request = json!({ "foo": "bar" });
        let (decision, _event) = evaluate_request(&request, now());
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "normalize_request");
    }

    #[test]
    fn denies_on_unsupported_spec_version() {
        let mut request = valid_request();
        request["spec_version"] = Value::String("9.9".to_string());
        let (decision, _event) = evaluate_request(&request, now());
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "normalize_request");
    }

    #[test]
    fn denies_when_email_domain_not_allowed() {
        let mut request = valid_request();
        request["audience"] = Value::String("tool:gmail".to_string());
        request["action"] = Value::String("gmail.send_message".to_string());
        request["runtime_context"] = json!({
            "target_email": "receiver@outside.org"
        });
        request["delegation_token"]["resource_constraints"] = json!({
            "email_domain_allowlist": ["example.com"]
        });
        resign_token(&mut request);

        let (decision, _event) = evaluate_request(&request, now());
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "evaluate_policy");
        assert_eq!(
            decision.reason,
            "target email domain not allowed by token resource constraints"
        );
    }

    #[test]
    fn simulates_policy_checks() {
        let mut request = valid_request();
        request["runtime_context"] = json!({
            "requested_spend": 10,
            "spend_currency": "USD"
        });
        request["delegation_token"]["max_spend"] = json!({
            "amount": 5,
            "currency": "USD"
        });
        request["delegation_token"]["max_delegation_depth"] = json!(0);
        resign_token(&mut request);

        let host_ctx = HostContext {
            delegation_depth: Some(1),
            ..HostContext::default()
        };
        let checks =
            simulate_request_policy(&request, &host_ctx).expect("policy simulation should succeed");
        assert!(checks.iter().any(|check| !check.passed));
        assert!(
            checks
                .iter()
                .any(|check| check.name == "max_spend" && !check.passed)
        );
        assert!(
            checks
                .iter()
                .any(|check| check.name == "delegation_depth" && !check.passed)
        );
    }

    #[test]
    fn denies_when_spend_currency_mismatches_token_max_spend_currency() {
        let mut request = valid_request();
        request["runtime_context"] = json!({
            "requested_spend": 10,
            "spend_currency": "EUR"
        });
        request["delegation_token"]["max_spend"] = json!({
            "amount": 20,
            "currency": "USD"
        });
        resign_token(&mut request);

        let (decision, _event) = evaluate_request(&request, now());
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "evaluate_policy");
        assert_eq!(
            decision.reason,
            "requested spend currency does not match token max_spend currency"
        );
    }

    #[test]
    fn denies_when_cognitive_thresholds_fail() {
        let request = valid_request();
        let trust_state = InMemoryTrustState::new();
        let host_ctx = HostContext {
            cognitive_judge_scores_bps: Some(vec![6000, 5800]),
            cognitive_challenge_pass_bps: Some(7000),
            ..HostContext::default()
        };

        let (decision, _event) =
            evaluate_request_with_state(&request, now(), &trust_state, &host_ctx);
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "evaluate_policy");
        assert_eq!(
            decision.reason,
            "cognitive average score is below hard-deny threshold"
        );
    }

    #[test]
    fn enforces_reputation_risk_multiplier() {
        let request = valid_request();
        let trust_state = InMemoryTrustState::new();
        let host_ctx = HostContext {
            reputation_score_bps: Some(3000),
            risk_challenge_passed: Some(false),
            extra_approval_granted: Some(false),
            ..HostContext::default()
        };

        let (decision, _event) =
            evaluate_request_with_state(&request, now(), &trust_state, &host_ctx);
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "evaluate_policy");
        assert_eq!(
            decision.reason,
            "low reputation requires additional challenge pass or explicit approval"
        );
    }

    #[test]
    fn denies_when_signature_verification_fails() {
        let mut request = valid_request();
        request["delegation_token"]["signature"] = json!("not-a-valid-signature");
        let (decision, _event) = evaluate_request(&request, now());
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "verify_signatures");
    }

    #[test]
    fn denies_when_identity_document_missing() {
        let mut request = valid_request();
        request["identity_document"] = Value::Null;
        let (decision, _event) = evaluate_request(&request, now());
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "validate_profile_compatibility");
    }

    #[test]
    fn denies_when_token_is_revoked() {
        use crate::revocation::TrustStateAdmin;
        let request = valid_request();
        let trust_state = InMemoryTrustState::new();
        let token_id = request["delegation_token"]["token_id"]
            .as_str()
            .expect("token_id should be present");
        trust_state
            .revoke_token(token_id)
            .expect("revoke should succeed");

        let (decision, _event) =
            evaluate_request_with_state(&request, now(), &trust_state, &HostContext::default());
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "enforce_revocation_and_redelegation");
        assert_eq!(decision.reason, "delegation token has been revoked");
    }

    #[test]
    fn denies_nonce_replay_with_shared_state() {
        let request = valid_request();
        let trust_state = InMemoryTrustState::new();

        let (first, _) =
            evaluate_request_with_state(&request, now(), &trust_state, &HostContext::default());
        let (second, _) =
            evaluate_request_with_state(&request, now(), &trust_state, &HostContext::default());

        assert!(first.allowed);
        assert!(!second.allowed);
        assert_eq!(second.stage, "enforce_revocation_and_redelegation");
        assert_eq!(second.reason, "delegation token nonce replay detected");
    }

    #[test]
    fn fails_closed_when_revocation_backend_unavailable() {
        let request = valid_request();
        let trust_state = InMemoryTrustState::new();
        trust_state.set_backend_available(false);

        let (decision, _) =
            evaluate_request_with_state(&request, now(), &trust_state, &HostContext::default());
        assert!(!decision.allowed);
        assert_eq!(decision.stage, "enforce_revocation_and_redelegation");
        assert_eq!(
            decision.reason,
            "revocation backend unavailable (fail-closed)"
        );
    }

    #[test]
    fn appends_audit_events_as_jsonl() {
        let (decision, event) = evaluate_request(&valid_request(), now());
        assert!(decision.allowed);

        let path = std::env::temp_dir().join(format!(
            "signet_audit_{}.jsonl",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        ));

        append_audit_event(&path, &event).expect("audit append should succeed");
        let contents = std::fs::read_to_string(&path).expect("audit file should exist");
        std::fs::remove_file(&path).expect("temporary audit file should be removable");
        assert!(contents.contains("\"allowed\":true"));
        assert!(contents.contains("\"token_id\":\"dlg_01J0EXAMPLE_"));
    }

    #[test]
    fn runtime_config_uses_durable_state_by_path() {
        let request = valid_request();
        let path = std::env::temp_dir().join(format!(
            "delegated_runtime_state_{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        ));
        let config = crate::revocation::RuntimeTrustConfig::durable_path(path.clone());

        let (first, _) = evaluate_request_with_runtime_config(&request, now(), &config);
        let (second, _) = evaluate_request_with_runtime_config(&request, now(), &config);

        assert!(first.allowed);
        assert!(!second.allowed);
        assert_eq!(second.stage, "enforce_revocation_and_redelegation");
        assert_eq!(second.reason, "delegation token nonce replay detected");
        std::fs::remove_file(&path).expect("state file should be removable");
    }

    #[test]
    fn evaluates_and_writes_allow_and_deny_audits() {
        let path = std::env::temp_dir().join(format!(
            "delegated_sink_{}.jsonl",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        ));
        let sink = JsonlFileAuditSink::new(path.clone());

        let allow_decision =
            evaluate_and_audit(&valid_request(), now(), &sink).expect("allow path should write");
        assert!(allow_decision.allowed);

        let mut deny_request = valid_request();
        deny_request["action"] = Value::String("calendar.delete_event".to_string());
        let deny_decision =
            evaluate_and_audit(&deny_request, now(), &sink).expect("deny path should write");
        assert!(!deny_decision.allowed);

        let contents = std::fs::read_to_string(&path).expect("audit file should exist");
        std::fs::remove_file(&path).expect("temporary audit file should be removable");
        assert_eq!(contents.lines().count(), 2);
        assert!(contents.contains("\"allowed\":true"));
        assert!(contents.contains("\"allowed\":false"));
    }

    #[test]
    fn custom_policy_can_deny_otherwise_valid_request() {
        use crate::models::PolicyCheck;

        struct AlwaysDenyPolicy;
        impl Policy for AlwaysDenyPolicy {
            fn evaluate(
                &self,
                _envelope: &RequestEnvelope,
                _host_context: &HostContext,
            ) -> Vec<PolicyCheck> {
                vec![PolicyCheck {
                    name: "custom_deny".to_string(),
                    passed: false,
                    reason: "denied by custom policy".to_string(),
                }]
            }
        }

        let trust_state = InMemoryTrustState::new();
        let (decision, _) = evaluate_request_with_policy(
            &valid_request(),
            now(),
            &trust_state,
            &HostContext::default(),
            &AlwaysDenyPolicy,
        );
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "denied by custom policy");
    }

    #[test]
    fn simulate_with_custom_policy_returns_custom_checks() {
        use crate::models::PolicyCheck;

        struct DoubleCheckPolicy;
        impl Policy for DoubleCheckPolicy {
            fn evaluate(
                &self,
                envelope: &RequestEnvelope,
                host_context: &HostContext,
            ) -> Vec<PolicyCheck> {
                let mut checks = DefaultPolicy.evaluate(envelope, host_context);
                checks.push(PolicyCheck {
                    name: "custom_check".to_string(),
                    passed: true,
                    reason: "custom check passed".to_string(),
                });
                checks
            }
        }

        let checks = simulate_request_policy_with_policy(
            &valid_request(),
            &HostContext::default(),
            &DoubleCheckPolicy,
        )
        .expect("simulation should succeed");
        assert!(checks.iter().any(|c| c.name == "custom_check"));
        assert!(checks.iter().any(|c| c.name == "allowed_actions"));
    }
}
