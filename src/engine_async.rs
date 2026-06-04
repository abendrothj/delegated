use crate::audit::{AuditSink, write_audit_event};
use crate::engine::{apply_policy_checks, from_envelope, from_raw};
use crate::models::{AuditEvent, Decision, HostContext, PolicyCheck, RequestEnvelope, Violation};
use crate::policy_trait::{DefaultPolicy, Policy};
use crate::profiles::validate_profile_compatibility;
use crate::revocation_async::AsyncTrustStateStore;
use crate::stages::{
    normalize_request, validate_identity_document_lifetime, validate_token_binding,
    validate_token_lifetime, verify_signatures,
};
use crate::stages_async::enforce_revocation_and_redelegation_async;
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use std::io;

pub async fn evaluate_request_with_async_state(
    raw_request: &Value,
    now: DateTime<Utc>,
    trust_state: &dyn AsyncTrustStateStore,
    host_context: &HostContext,
) -> (Decision, AuditEvent) {
    evaluate_request_with_async_state_and_policy(
        raw_request,
        now,
        trust_state,
        host_context,
        &DefaultPolicy,
    )
    .await
}

pub async fn evaluate_request_with_async_state_and_policy(
    raw_request: &Value,
    now: DateTime<Utc>,
    trust_state: &dyn AsyncTrustStateStore,
    host_context: &HostContext,
    policy: &dyn Policy,
) -> (Decision, AuditEvent) {
    let leeway = Duration::seconds(host_context.clock_leeway_secs as i64);

    let result: Result<RequestEnvelope, Violation> = async {
        let envelope = normalize_request(raw_request)?;
        let envelope = validate_profile_compatibility(envelope)?;
        let envelope = verify_signatures(envelope)?;
        let envelope = validate_identity_document_lifetime(envelope, now, leeway)?;
        let envelope =
            enforce_revocation_and_redelegation_async(envelope, trust_state, host_context).await?;
        let envelope = validate_token_lifetime(envelope, now, leeway)?;
        let envelope = validate_token_binding(envelope)?;
        apply_policy_checks(envelope, host_context, policy)
    }
    .await;

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

pub async fn evaluate_and_audit_with_async_state(
    raw_request: &Value,
    now: DateTime<Utc>,
    sink: &dyn AuditSink,
    trust_state: &dyn AsyncTrustStateStore,
    host_context: &HostContext,
) -> io::Result<Decision> {
    evaluate_and_audit_with_async_state_and_policy(
        raw_request,
        now,
        sink,
        trust_state,
        host_context,
        &DefaultPolicy,
    )
    .await
}

pub async fn evaluate_and_audit_with_async_state_and_policy(
    raw_request: &Value,
    now: DateTime<Utc>,
    sink: &dyn AuditSink,
    trust_state: &dyn AsyncTrustStateStore,
    host_context: &HostContext,
    policy: &dyn Policy,
) -> io::Result<Decision> {
    let (decision, event) = evaluate_request_with_async_state_and_policy(
        raw_request,
        now,
        trust_state,
        host_context,
        policy,
    )
    .await;
    write_audit_event(sink, &event)?;
    Ok(decision)
}

pub async fn simulate_request_policy_async(
    raw_request: &Value,
    host_context: &HostContext,
    policy: &dyn Policy,
) -> Result<Vec<PolicyCheck>, Violation> {
    let envelope = normalize_request(raw_request)?;
    Ok(policy.evaluate(&envelope, host_context))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::JsonlFileAuditSink;
    use crate::crypto::{
        TOKEN_SIGNATURE_ALG_ED25519, sign_delegation_token, sign_identity_document,
    };
    use crate::models::{
        AgentEndpoint, AgentIdentityDocument, DelegationToken, PolicyCheck, PublicKeyRecord,
        RequestEnvelope, RuntimeContext, TrustProfile,
    };
    use crate::revocation_async::InMemoryAsyncTrustState;
    use base64ct::{Base64UrlUnpadded, Encoding};
    use chrono::TimeZone;
    use ed25519_dalek::SigningKey;
    use std::sync::atomic::{AtomicU64, Ordering};

    static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 1, 20, 20, 0)
            .single()
            .expect("valid test timestamp")
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
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
        let mut identity = AgentIdentityDocument {
            spec_version: "0.1".to_string(),
            kind: "AgentIdentityDocument".to_string(),
            agent_id: "agent:example:scheduler:v1".to_string(),
            display_name: Some("Async Scheduler".to_string()),
            owner_id: "org:example".to_string(),
            issuer: "https://trust.example.ai".to_string(),
            identity_type: "spiffe".to_string(),
            subject: "spiffe://example.ai/agents/scheduler".to_string(),
            public_keys: vec![PublicKeyRecord {
                kid: "key-2026-01".to_string(),
                kty: "OKP".to_string(),
                crv: Some(TOKEN_SIGNATURE_ALG_ED25519.to_string()),
                x: Some(Base64UrlUnpadded::encode_string(&key.verifying_key().to_bytes())),
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
        identity.signature = sign_identity_document(&identity, &key).expect("identity signing");

        let mut token = DelegationToken {
            spec_version: "0.1".to_string(),
            kind: "DelegationToken".to_string(),
            token_id: format!("dlg_async_{unique_id}"),
            issuer: "https://trust.example.ai".to_string(),
            agent_id: "agent:example:scheduler:v1".to_string(),
            delegator_id: "user:jake-abendroth".to_string(),
            owner_id: "org:example".to_string(),
            audience: vec!["tool:google-calendar".to_string()],
            allowed_actions: vec!["calendar.create_event".to_string()],
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
            intent: None,
            nonce: format!("nonce-async-{unique_id}"),
            key_id: "key-2026-01".to_string(),
            signature_alg: TOKEN_SIGNATURE_ALG_ED25519.to_string(),
            signature: String::new(),
        };
        token.signature = sign_delegation_token(&token, &key).expect("token signing");

        let envelope = RequestEnvelope {
            spec_version: "0.1".to_string(),
            kind: "TrustRequestEnvelope".to_string(),
            request_id: Some(format!("req_async_{unique_id}")),
            profile: TrustProfile::Developer,
            agent_id: "agent:example:scheduler:v1".to_string(),
            delegator_id: "user:jake-abendroth".to_string(),
            audience: "tool:google-calendar".to_string(),
            action: "calendar.create_event".to_string(),
            resource: None,
            runtime_context: RuntimeContext::default(),
            identity_document: Some(identity),
            token,
        };
        serde_json::to_value(envelope).expect("serialization should work")
    }

    #[tokio::test]
    async fn async_allows_valid_request() {
        let state = InMemoryAsyncTrustState::new();
        let (decision, _) =
            evaluate_request_with_async_state(&valid_request(), now(), &state, &HostContext::default())
                .await;
        assert!(decision.allowed, "unexpected deny: {}", decision.reason);
    }

    #[tokio::test]
    async fn async_denies_nonce_replay() {
        let state = InMemoryAsyncTrustState::new();
        let request = valid_request();
        let (first, _) =
            evaluate_request_with_async_state(&request, now(), &state, &HostContext::default())
                .await;
        let (second, _) =
            evaluate_request_with_async_state(&request, now(), &state, &HostContext::default())
                .await;
        assert!(first.allowed);
        assert!(!second.allowed);
        assert_eq!(second.stage, "enforce_revocation_and_redelegation");
        assert_eq!(second.reason, "delegation token nonce replay detected");
    }

    #[tokio::test]
    async fn async_custom_policy_can_deny() {
        struct AlwaysDenyPolicy;
        impl Policy for AlwaysDenyPolicy {
            fn evaluate(
                &self,
                _: &RequestEnvelope,
                _: &HostContext,
            ) -> Vec<PolicyCheck> {
                vec![PolicyCheck {
                    name: "custom_deny".to_string(),
                    passed: false,
                    reason: "custom policy denied".to_string(),
                }]
            }
        }

        let state = InMemoryAsyncTrustState::new();
        let (decision, _) = evaluate_request_with_async_state_and_policy(
            &valid_request(),
            now(),
            &state,
            &HostContext::default(),
            &AlwaysDenyPolicy,
        )
        .await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "custom policy denied");
    }

    #[tokio::test]
    async fn async_writes_audit_events() {
        let state = InMemoryAsyncTrustState::new();
        let path = std::env::temp_dir().join(format!(
            "delegated_async_audit_{}.jsonl",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        ));
        let sink = JsonlFileAuditSink::new(path.clone());
        let decision = evaluate_and_audit_with_async_state(
            &valid_request(),
            now(),
            &sink,
            &state,
            &HostContext::default(),
        )
        .await
        .expect("audit should succeed");
        assert!(decision.allowed);
        let contents = std::fs::read_to_string(&path).expect("audit file should exist");
        std::fs::remove_file(&path).expect("temp file should be removable");
        assert!(contents.contains("\"allowed\":true"));
    }
}
