use crate::contracts::validate_request_contract;
use crate::crypto::{verify_delegation_token_signature, verify_identity_document_signature};
use crate::models::{HostContext, RequestEnvelope, Violation};
use crate::revocation::TrustStateStore;
use chrono::{DateTime, Duration, Utc};
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
    leeway: Duration,
) -> Result<RequestEnvelope, Violation> {
    if envelope.token.issued_at > now + leeway {
        return Err(Violation::new(
            "validate_token_lifetime",
            "delegation token not active yet",
        ));
    }

    if envelope.token.expires_at + leeway <= now {
        return Err(Violation::new(
            "validate_token_lifetime",
            "delegation token expired",
        ));
    }

    Ok(envelope)
}

pub fn validate_identity_document_lifetime(
    envelope: RequestEnvelope,
    now: DateTime<Utc>,
    leeway: Duration,
) -> Result<RequestEnvelope, Violation> {
    let identity_document = envelope.identity_document.as_ref().ok_or_else(|| {
        Violation::new(
            "validate_identity_document_lifetime",
            "identity_document is required for lifetime checks",
        )
    })?;
    if identity_document.expires_at + leeway <= now {
        return Err(Violation::new(
            "validate_identity_document_lifetime",
            "identity document expired",
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

#[cfg(feature = "oidc-bridge")]
pub fn verify_signatures_with_verifier(
    envelope: RequestEnvelope,
    verifier: Option<&dyn crate::identity_verifier::IdentityVerifier>,
) -> Result<RequestEnvelope, Violation> {
    let identity_document = envelope.identity_document.as_ref().ok_or_else(|| {
        Violation::new(
            "verify_signatures",
            "identity_document is required for signature verification",
        )
    })?;

    match verifier {
        Some(v) => {
            v.verify(identity_document)?;
            // Even with OIDC verification, still verify the delegation token
            // signature against the public key in the identity document.
            crate::crypto::verify_delegation_token_signature(
                &envelope.token,
                identity_document,
            )?;
            Ok(envelope)
        }
        None => verify_signatures(envelope),
    }
}

pub fn enforce_revocation_and_redelegation(
    envelope: RequestEnvelope,
    state: &dyn TrustStateStore,
    host_context: &HostContext,
) -> Result<RequestEnvelope, Violation> {
    let is_revoked = state
        .is_token_revoked(&envelope.token.token_id)
        .map_err(|reason| {
            Violation::new(
                "enforce_revocation_and_redelegation",
                format!("{reason} (fail-closed)"),
            )
        })?;
    if is_revoked {
        return Err(Violation::new(
            "enforce_revocation_and_redelegation",
            "delegation token has been revoked",
        ));
    }

    let is_agent_denied = state
        .is_agent_emergency_denied(&envelope.agent_id)
        .map_err(|reason| {
            Violation::new(
                "enforce_revocation_and_redelegation",
                format!("{reason} (fail-closed)"),
            )
        })?;
    if is_agent_denied {
        return Err(Violation::new(
            "enforce_revocation_and_redelegation",
            "agent is blocked by emergency deny list",
        ));
    }

    let nonce_was_new = state
        .consume_nonce(&envelope.token.nonce, envelope.token.expires_at)
        .map_err(|reason| {
            Violation::new(
                "enforce_revocation_and_redelegation",
                format!("{reason} (fail-closed)"),
            )
        })?;
    if !nonce_was_new {
        return Err(Violation::new(
            "enforce_revocation_and_redelegation",
            "delegation token nonce replay detected",
        ));
    }

    if let Some(max_depth) = envelope.token.max_delegation_depth {
        let runtime_depth = host_context.delegation_depth.unwrap_or(0);
        if runtime_depth > max_depth {
            return Err(Violation::new(
                "enforce_revocation_and_redelegation",
                "runtime delegation depth exceeds token max_delegation_depth",
            ));
        }
    }

    Ok(envelope)
}
