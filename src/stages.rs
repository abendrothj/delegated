use crate::contracts::validate_request_contract;
use crate::crypto::{verify_delegation_token_signature, verify_identity_document_signature};
use crate::models::{RequestEnvelope, Violation};
use chrono::{DateTime, Utc};
use serde_json::Value;

pub fn normalize_request(raw_request: &Value) -> Result<RequestEnvelope, Violation> {
    let envelope: RequestEnvelope = serde_json::from_value(raw_request.clone()).map_err(|err| {
        Violation::new(
            "normalize_request",
            format!("request does not match contract: {err}"),
        )
    })?;

    validate_request_contract(&envelope)?;
    Ok(envelope)
}

pub fn validate_token_lifetime(
    envelope: RequestEnvelope,
    now: DateTime<Utc>,
) -> Result<RequestEnvelope, Violation> {
    if envelope.token.issued_at > now {
        return Err(Violation::new(
            "validate_token_lifetime",
            "delegation token not active yet",
        ));
    }

    if envelope.token.expires_at <= now {
        return Err(Violation::new(
            "validate_token_lifetime",
            "delegation token expired",
        ));
    }

    Ok(envelope)
}

pub fn validate_token_binding(envelope: RequestEnvelope) -> Result<RequestEnvelope, Violation> {
    if envelope.token.agent_id != envelope.agent_id {
        return Err(Violation::new(
            "validate_token_binding",
            "token agent_id does not match request agent_id",
        ));
    }

    if envelope.token.delegator_id != envelope.delegator_id {
        return Err(Violation::new(
            "validate_token_binding",
            "token delegator_id does not match request delegator_id",
        ));
    }

    if !envelope.token.audience.contains(&envelope.audience) {
        return Err(Violation::new(
            "validate_token_binding",
            "request audience not in token audience",
        ));
    }

    Ok(envelope)
}

pub fn verify_signatures(envelope: RequestEnvelope) -> Result<RequestEnvelope, Violation> {
    let identity_document = envelope.identity_document.as_ref().ok_or_else(|| {
        Violation::new(
            "verify_signatures",
            "identity_document is required for offline signature verification",
        )
    })?;

    if identity_document.issuer != envelope.token.issuer {
        return Err(Violation::new(
            "verify_signatures",
            "delegation token issuer does not match identity document issuer",
        ));
    }
    if identity_document.agent_id != envelope.token.agent_id {
        return Err(Violation::new(
            "verify_signatures",
            "delegation token agent_id does not match identity document agent_id",
        ));
    }
    if identity_document.owner_id != envelope.token.owner_id {
        return Err(Violation::new(
            "verify_signatures",
            "delegation token owner_id does not match identity document owner_id",
        ));
    }

    verify_identity_document_signature(identity_document)?;
    verify_delegation_token_signature(&envelope.token, identity_document)?;
    Ok(envelope)
}
