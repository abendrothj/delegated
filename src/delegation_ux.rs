use crate::models::MaxSpend;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationGrantProposal {
    pub request_id: String,
    pub delegator_id: String,
    pub agent_id: String,
    pub owner_id: String,
    pub intent: String,
    pub audience: Vec<String>,
    pub allowed_actions: Vec<String>,
    pub max_spend: Option<MaxSpend>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalDecision {
    Approve,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsentStatus {
    Approved,
    Denied,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentReceipt {
    pub receipt_id: String,
    pub request_id: String,
    pub status: ConsentStatus,
    pub actor_id: String,
    pub reason: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub token_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalCallbackPayload {
    pub receipt_id: String,
    pub request_id: String,
    pub status: ConsentStatus,
    pub actor_id: String,
    pub issued_at: DateTime<Utc>,
}

pub fn render_cli_grant_summary(proposal: &DelegationGrantProposal) -> String {
    let mut lines = vec![
        format!("Request ID: {}", proposal.request_id),
        format!("Delegator: {}", proposal.delegator_id),
        format!("Agent: {}", proposal.agent_id),
        format!("Owner: {}", proposal.owner_id),
        format!("Intent: {}", proposal.intent),
        format!("Audience: {}", proposal.audience.join(", ")),
        format!("Allowed actions: {}", proposal.allowed_actions.join(", ")),
        format!("Expires at: {}", proposal.expires_at.to_rfc3339()),
    ];

    if let Some(max_spend) = proposal.max_spend.as_ref() {
        lines.push(format!(
            "Max spend: {} {}",
            max_spend.amount, max_spend.currency
        ));
    } else {
        lines.push("Max spend: none".to_string());
    }

    lines.push("Decision options: approve | deny".to_string());
    lines.join("\n")
}

pub fn issue_consent_receipt(
    proposal: &DelegationGrantProposal,
    decision: ApprovalDecision,
    actor_id: impl Into<String>,
    reason: Option<String>,
    issued_at: DateTime<Utc>,
    token_id: Option<String>,
) -> ConsentReceipt {
    let status = match decision {
        ApprovalDecision::Approve => ConsentStatus::Approved,
        ApprovalDecision::Deny => ConsentStatus::Denied,
    };

    ConsentReceipt {
        receipt_id: format!("rcpt_{}_{}", proposal.request_id, issued_at.timestamp()),
        request_id: proposal.request_id.clone(),
        status,
        actor_id: actor_id.into(),
        reason,
        issued_at,
        token_id,
    }
}

pub fn issue_revocation_receipt(
    request_id: impl Into<String>,
    actor_id: impl Into<String>,
    reason: Option<String>,
    issued_at: DateTime<Utc>,
    token_id: String,
) -> ConsentReceipt {
    let request_id = request_id.into();
    ConsentReceipt {
        receipt_id: format!("rcpt_{}_{}", request_id, issued_at.timestamp()),
        request_id,
        status: ConsentStatus::Revoked,
        actor_id: actor_id.into(),
        reason,
        issued_at,
        token_id: Some(token_id),
    }
}

pub fn to_approval_callback(receipt: &ConsentReceipt) -> ApprovalCallbackPayload {
    ApprovalCallbackPayload {
        receipt_id: receipt.receipt_id.clone(),
        request_id: receipt.request_id.clone(),
        status: receipt.status,
        actor_id: receipt.actor_id.clone(),
        issued_at: receipt.issued_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sample_proposal() -> DelegationGrantProposal {
        DelegationGrantProposal {
            request_id: "req_cli_123".to_string(),
            delegator_id: "user:jake-abendroth".to_string(),
            agent_id: "agent:example:scheduler:v1".to_string(),
            owner_id: "org:example".to_string(),
            intent: "schedule_demo_and_send_confirmation".to_string(),
            audience: vec!["tool:google-calendar".to_string(), "tool:gmail".to_string()],
            allowed_actions: vec![
                "calendar.create_event".to_string(),
                "gmail.send_message".to_string(),
            ],
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

    #[test]
    fn renders_cli_summary_with_required_sections() {
        let summary = render_cli_grant_summary(&sample_proposal());
        assert!(summary.contains("Request ID: req_cli_123"));
        assert!(summary.contains("Decision options: approve | deny"));
    }

    #[test]
    fn builds_approval_receipt_and_callback() {
        let now = Utc
            .with_ymd_and_hms(2026, 6, 1, 20, 11, 0)
            .single()
            .expect("valid timestamp");
        let receipt = issue_consent_receipt(
            &sample_proposal(),
            ApprovalDecision::Approve,
            "user:jake-abendroth",
            Some("approved in CLI".to_string()),
            now,
            Some("dlg_01J0EXAMPLE".to_string()),
        );
        assert_eq!(receipt.status, ConsentStatus::Approved);
        assert_eq!(receipt.token_id.as_deref(), Some("dlg_01J0EXAMPLE"));

        let callback = to_approval_callback(&receipt);
        assert_eq!(callback.status, ConsentStatus::Approved);
        assert_eq!(callback.request_id, "req_cli_123");
    }

    #[test]
    fn builds_revocation_receipt() {
        let now = Utc
            .with_ymd_and_hms(2026, 6, 1, 20, 25, 0)
            .single()
            .expect("valid timestamp");
        let receipt = issue_revocation_receipt(
            "req_cli_123",
            "user:jake-abendroth",
            Some("manual revoke".to_string()),
            now,
            "dlg_01J0EXAMPLE".to_string(),
        );
        assert_eq!(receipt.status, ConsentStatus::Revoked);
        assert_eq!(receipt.token_id.as_deref(), Some("dlg_01J0EXAMPLE"));
    }
}
