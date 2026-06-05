use crate::audit::{AuditQuery, AuditReader, read_audit_events};
use crate::delegation_ux::{
    ApprovalCallbackPayload, ApprovalDecision, ConsentReceipt, DelegationGrantProposal,
    issue_consent_receipt, issue_revocation_receipt, to_approval_callback,
};
use crate::engine::simulate_request_policy;
use crate::models::{AuditEvent, HostContext, PolicyCheck, Violation};
use crate::revocation::TrustStateAdmin;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalOperation {
    pub receipt: ConsentReceipt,
    pub callback: ApprovalCallbackPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationOperation {
    pub receipt: ConsentReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySimulationResult {
    pub checks: Vec<PolicyCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationalReport {
    pub total_events: usize,
    pub allowed_events: usize,
    pub denied_events: usize,
    pub stage_counts: HashMap<String, usize>,
}

pub fn record_approval_decision(
    proposal: &DelegationGrantProposal,
    decision: ApprovalDecision,
    actor_id: impl Into<String>,
    reason: Option<String>,
    issued_at: DateTime<Utc>,
    token_id: Option<String>,
) -> ApprovalOperation {
    let receipt = issue_consent_receipt(proposal, decision, actor_id, reason, issued_at, token_id);
    let callback = to_approval_callback(&receipt);
    ApprovalOperation { receipt, callback }
}

pub fn revoke_token_with_receipt(
    trust_state: &dyn TrustStateAdmin,
    request_id: impl Into<String>,
    token_id: String,
    actor_id: impl Into<String>,
    reason: Option<String>,
    issued_at: DateTime<Utc>,
) -> Result<RevocationOperation, Violation> {
    trust_state
        .revoke_token(&token_id)
        .map_err(|error| Violation::new("control_plane_revoke", error.to_string()))?;
    let receipt = issue_revocation_receipt(request_id, actor_id, reason, issued_at, token_id);
    Ok(RevocationOperation { receipt })
}

pub fn emergency_deny_agent(
    trust_state: &dyn TrustStateAdmin,
    agent_id: impl Into<String>,
) -> Result<(), Violation> {
    let agent_id = agent_id.into();
    trust_state
        .emergency_deny_agent(&agent_id)
        .map_err(|error| Violation::new("control_plane_emergency_deny", error.to_string()))
}

/// Runs policy checks only, using a default [`HostContext`].
///
/// # Security — does not verify signatures, lifetimes, or revocation
///
/// This is a convenience wrapper around [`simulate_policy_with_host_context`] with
/// `HostContext::default()`. It shares the same security caveats: signatures,
/// lifetimes, and revocation are **not** checked. Use for policy preview only.
pub fn simulate_policy(raw_request: &Value) -> Result<PolicySimulationResult, Violation> {
    simulate_policy_with_host_context(raw_request, &HostContext::default())
}

/// Runs policy checks only, using the supplied [`HostContext`] for host-side signals.
///
/// # Security — does not verify signatures, lifetimes, or revocation
///
/// This function **skips** the full trust pipeline:
/// - Ed25519 signatures are **not verified**
/// - Token and identity document lifetimes are **not checked**
/// - The revocation store, emergency deny list, and nonce replay protection are **not consulted**
///
/// Intended for policy preview, UI configuration, and integration testing. For production
/// enforcement, use [`evaluate_request_with_state`] or the axum [`DelegatedLayer`].
pub fn simulate_policy_with_host_context(
    raw_request: &Value,
    host_context: &HostContext,
) -> Result<PolicySimulationResult, Violation> {
    let checks = simulate_request_policy(raw_request, host_context)?;
    Ok(PolicySimulationResult { checks })
}

pub fn export_audit_events(
    reader: &dyn AuditReader,
    query: AuditQuery,
) -> Result<Vec<AuditEvent>, Violation> {
    read_audit_events(reader, query)
        .map_err(|error| Violation::new("control_plane_audit_export", error.to_string()))
}

pub fn build_operational_report(
    reader: &dyn AuditReader,
    query: AuditQuery,
) -> Result<OperationalReport, Violation> {
    let events = export_audit_events(reader, query)?;
    let mut stage_counts: HashMap<String, usize> = HashMap::new();
    let mut allowed_events = 0usize;
    let mut denied_events = 0usize;
    for event in &events {
        if event.allowed {
            allowed_events += 1;
        } else {
            denied_events += 1;
        }
        *stage_counts.entry(event.stage.clone()).or_insert(0) += 1;
    }
    Ok(OperationalReport {
        total_events: events.len(),
        allowed_events,
        denied_events,
        stage_counts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditSink, JsonlFileAuditSink};
    use crate::models::MaxSpend;
    use crate::revocation::{InMemoryTrustState, TrustStateStore};
    use chrono::TimeZone;
    use serde_json::json;

    fn sample_proposal() -> DelegationGrantProposal {
        DelegationGrantProposal {
            request_id: "req_cp_123".to_string(),
            delegator_id: "user:jake-abendroth".to_string(),
            agent_id: "agent:example:scheduler:v1".to_string(),
            owner_id: "org:example".to_string(),
            intent: "schedule_demo".to_string(),
            audience: vec!["tool:google-calendar".to_string()],
            allowed_actions: vec!["calendar.create_event".to_string()],
            max_spend: Some(MaxSpend {
                amount: 0,
                currency: "USD".to_string(),
            }),
            expires_at: Utc
                .with_ymd_and_hms(2026, 6, 1, 20, 40, 0)
                .single()
                .expect("valid timestamp"),
        }
    }

    fn sample_policy_simulation_request(max_depth: u16) -> Value {
        json!({
            "spec_version": "0.1",
            "kind": "TrustRequestEnvelope",
            "request_id": "req_sim_1",
            "profile": "developer",
            "agent_id": "agent:example:scheduler:v1",
            "delegator_id": "user:alice",
            "audience": "tool:google-calendar",
            "action": "calendar.create_event",
            "runtime_context": {},
            "identity_document": null,
            "delegation_token": {
                "spec_version": "0.1",
                "kind": "DelegationToken",
                "token_id": "dlg_sim_1",
                "issuer": "https://trust.example.ai",
                "agent_id": "agent:example:scheduler:v1",
                "delegator_id": "user:alice",
                "owner_id": "org:example",
                "audience": ["tool:google-calendar"],
                "allowed_actions": ["calendar.create_event"],
                "max_delegation_depth": max_depth,
                "issued_at": "2026-06-01T20:10:00Z",
                "expires_at": "2026-06-01T20:40:00Z",
                "nonce": "nonce-sim-1",
                "key_id": "key-2026-01",
                "signature_alg": "Ed25519",
                "signature": "sig"
            }
        })
    }

    #[test]
    fn records_approval_and_callback() {
        let now = Utc
            .with_ymd_and_hms(2026, 6, 1, 20, 11, 0)
            .single()
            .expect("valid timestamp");
        let operation = record_approval_decision(
            &sample_proposal(),
            ApprovalDecision::Approve,
            "user:jake-abendroth",
            Some("approved".to_string()),
            now,
            Some("dlg_1".to_string()),
        );
        assert_eq!(operation.receipt.request_id, "req_cp_123");
        assert_eq!(operation.callback.request_id, "req_cp_123");
    }

    #[test]
    fn revokes_token_with_receipt() {
        let state = InMemoryTrustState::new();
        let now = Utc
            .with_ymd_and_hms(2026, 6, 1, 20, 25, 0)
            .single()
            .expect("valid timestamp");
        let operation = revoke_token_with_receipt(
            &state,
            "req_cp_123",
            "dlg_1".to_string(),
            "user:jake-abendroth",
            Some("manual revoke".to_string()),
            now,
        )
        .expect("revocation should succeed");
        assert_eq!(operation.receipt.token_id.as_deref(), Some("dlg_1"));
        assert!(
            state
                .is_token_revoked("dlg_1")
                .expect("state query should succeed")
        );
    }

    #[test]
    fn builds_report_from_exported_audit_events() {
        let path = std::env::temp_dir().join(format!(
            "delegated_cp_audit_{}.jsonl",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_nanos()
        ));
        let sink = JsonlFileAuditSink::new(path.clone());
        sink.write_event(&AuditEvent {
            occurred_at: Utc
                .with_ymd_and_hms(2026, 6, 1, 20, 20, 0)
                .single()
                .expect("valid timestamp"),
            allowed: true,
            stage: "evaluate_policy".to_string(),
            reason: "ok".to_string(),
            request_id: Some("1".to_string()),
            agent_id: Some("a".to_string()),
            delegator_id: Some("d".to_string()),
            audience: Some("tool".to_string()),
            action: Some("act".to_string()),
            token_id: Some("t".to_string()),
        })
        .expect("write should succeed");
        sink.write_event(&AuditEvent {
            occurred_at: Utc
                .with_ymd_and_hms(2026, 6, 1, 20, 21, 0)
                .single()
                .expect("valid timestamp"),
            allowed: false,
            stage: "verify_signatures".to_string(),
            reason: "denied".to_string(),
            request_id: Some("2".to_string()),
            agent_id: Some("a".to_string()),
            delegator_id: Some("d".to_string()),
            audience: Some("tool".to_string()),
            action: Some("act".to_string()),
            token_id: Some("t".to_string()),
        })
        .expect("write should succeed");

        let report = build_operational_report(
            &sink,
            AuditQuery {
                since: None,
                limit: 10,
                order: crate::audit::AuditOrder::NewestFirst,
            },
        )
        .expect("report should build");
        assert_eq!(report.total_events, 2);
        assert_eq!(report.allowed_events, 1);
        assert_eq!(report.denied_events, 1);
        std::fs::remove_file(path).expect("temporary audit file should be removable");
    }

    #[test]
    fn simulation_accepts_explicit_host_context() {
        let request = sample_policy_simulation_request(0);
        let denied = simulate_policy_with_host_context(
            &request,
            &HostContext {
                delegation_depth: Some(1),
                ..HostContext::default()
            },
        )
        .expect("context-aware simulation should succeed");
        assert!(
            denied
                .checks
                .iter()
                .any(|check| check.name == "delegation_depth" && !check.passed)
        );

        let host_context = HostContext {
            delegation_depth: Some(0),
            ..HostContext::default()
        };
        let allowed = simulate_policy_with_host_context(&request, &host_context)
            .expect("context-aware simulation should succeed");
        assert!(
            allowed
                .checks
                .iter()
                .any(|check| check.name == "delegation_depth" && check.passed)
        );
    }
}
