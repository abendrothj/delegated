use crate::crypto::TOKEN_SIGNATURE_ALG_ED25519;
use crate::models::{AgentIdentityDocument, DelegationToken, RequestEnvelope, Violation};

/// The spec version this build was compiled against. Use this constant in issuance
/// code so that bumping the protocol version only requires changing it here.
pub const SPEC_VERSION_CURRENT: &str = "0.1";

/// All spec versions this build can evaluate. Validators check membership here,
/// not equality against a single version, so callers holding older tokens
/// continue to work after a protocol bump until explicitly removed.
pub const SUPPORTED_SPEC_VERSIONS: &[&str] = &["0.1"];

#[deprecated(since = "0.1.0", note = "Use SPEC_VERSION_CURRENT instead")]
pub const SPEC_VERSION_V0_1: &str = "0.1";

pub const KIND_TRUST_REQUEST_ENVELOPE: &str = "TrustRequestEnvelope";
pub const KIND_DELEGATION_TOKEN: &str = "DelegationToken";
pub const KIND_AGENT_IDENTITY_DOCUMENT: &str = "AgentIdentityDocument";

pub fn validate_request_contract(envelope: &RequestEnvelope) -> Result<(), Violation> {
    validate_spec_version("request.spec_version", &envelope.spec_version)?;
    validate_kind("request.kind", &envelope.kind, KIND_TRUST_REQUEST_ENVELOPE)?;
    validate_non_empty("request.agent_id", &envelope.agent_id)?;
    validate_non_empty("request.delegator_id", &envelope.delegator_id)?;
    validate_non_empty("request.audience", &envelope.audience)?;
    validate_non_empty("request.action", &envelope.action)?;
    validate_runtime_context(envelope)?;

    if let Some(request_id) = envelope.request_id.as_ref() {
        validate_non_empty("request.request_id", request_id)?;
    }
    if let Some(resource) = envelope.resource.as_ref() {
        validate_non_empty("request.resource", resource)?;
    }

    validate_delegation_token(&envelope.token)?;

    if let Some(identity_document) = envelope.identity_document.as_ref() {
        validate_identity_document(identity_document)?;
        if identity_document.agent_id != envelope.agent_id {
            return Err(Violation::new(
                "normalize_request",
                "identity_document.agent_id must match request.agent_id",
            ));
        }
    }

    Ok(())
}

fn validate_delegation_token(token: &DelegationToken) -> Result<(), Violation> {
    validate_spec_version("delegation_token.spec_version", &token.spec_version)?;
    validate_kind("delegation_token.kind", &token.kind, KIND_DELEGATION_TOKEN)?;
    validate_non_empty("delegation_token.token_id", &token.token_id)?;
    validate_non_empty("delegation_token.issuer", &token.issuer)?;
    validate_non_empty("delegation_token.agent_id", &token.agent_id)?;
    validate_non_empty("delegation_token.delegator_id", &token.delegator_id)?;
    validate_non_empty("delegation_token.owner_id", &token.owner_id)?;
    validate_non_empty("delegation_token.nonce", &token.nonce)?;
    validate_non_empty("delegation_token.key_id", &token.key_id)?;
    validate_non_empty("delegation_token.signature_alg", &token.signature_alg)?;
    validate_non_empty("delegation_token.signature", &token.signature)?;
    validate_non_empty_vec("delegation_token.audience", &token.audience)?;
    validate_non_empty_vec("delegation_token.allowed_actions", &token.allowed_actions)?;

    if let Some(intent) = token.intent.as_ref() {
        validate_non_empty("delegation_token.intent", intent)?;
    }

    if token.issued_at >= token.expires_at {
        return Err(Violation::new(
            "normalize_request",
            "delegation_token.issued_at must be before delegation_token.expires_at",
        ));
    }

    if let Some(constraints) = token.resource_constraints.as_ref() {
        if let Some(calendar_ids) = constraints.calendar_ids.as_ref() {
            validate_non_empty_vec(
                "delegation_token.resource_constraints.calendar_ids",
                calendar_ids,
            )?;
        }
        if let Some(allowlist) = constraints.email_domain_allowlist.as_ref() {
            validate_non_empty_vec(
                "delegation_token.resource_constraints.email_domain_allowlist",
                allowlist,
            )?;
        }
    }

    if let Some(max_spend) = token.max_spend.as_ref() {
        validate_non_empty("delegation_token.max_spend.currency", &max_spend.currency)?;
    }
    if token.signature_alg != TOKEN_SIGNATURE_ALG_ED25519 {
        return Err(Violation::new(
            "normalize_request",
            format!(
                "delegation_token.signature_alg must equal {}",
                TOKEN_SIGNATURE_ALG_ED25519
            ),
        ));
    }

    Ok(())
}

fn validate_identity_document(document: &AgentIdentityDocument) -> Result<(), Violation> {
    validate_spec_version("identity_document.spec_version", &document.spec_version)?;
    validate_kind(
        "identity_document.kind",
        &document.kind,
        KIND_AGENT_IDENTITY_DOCUMENT,
    )?;
    validate_non_empty("identity_document.agent_id", &document.agent_id)?;
    validate_non_empty("identity_document.owner_id", &document.owner_id)?;
    validate_non_empty("identity_document.issuer", &document.issuer)?;
    validate_non_empty("identity_document.identity_type", &document.identity_type)?;
    validate_non_empty("identity_document.subject", &document.subject)?;
    validate_non_empty("identity_document.signature", &document.signature)?;
    validate_non_empty_vec(
        "identity_document.supported_protocols",
        &document.supported_protocols,
    )?;
    validate_non_empty_vec(
        "identity_document.supported_auth_methods",
        &document.supported_auth_methods,
    )?;

    if let Some(display_name) = document.display_name.as_ref() {
        validate_non_empty("identity_document.display_name", display_name)?;
    }

    if document.public_keys.is_empty() {
        return Err(Violation::new(
            "normalize_request",
            "identity_document.public_keys must be a non-empty array",
        ));
    }
    for key in &document.public_keys {
        validate_non_empty("identity_document.public_keys[].kid", &key.kid)?;
        validate_non_empty("identity_document.public_keys[].kty", &key.kty)?;
        if key.kty != "OKP" {
            return Err(Violation::new(
                "normalize_request",
                "identity_document.public_keys[].kty must be OKP",
            ));
        }
        if let Some(crv) = key.crv.as_ref() {
            validate_non_empty("identity_document.public_keys[].crv", crv)?;
            if crv != TOKEN_SIGNATURE_ALG_ED25519 {
                return Err(Violation::new(
                    "normalize_request",
                    format!(
                        "identity_document.public_keys[].crv must equal {}",
                        TOKEN_SIGNATURE_ALG_ED25519
                    ),
                ));
            }
        } else {
            return Err(Violation::new(
                "normalize_request",
                "identity_document.public_keys[].crv is required",
            ));
        }
        if let Some(x) = key.x.as_ref() {
            validate_non_empty("identity_document.public_keys[].x", x)?;
        } else {
            return Err(Violation::new(
                "normalize_request",
                "identity_document.public_keys[].x is required",
            ));
        }
    }

    if document.endpoints.is_empty() {
        return Err(Violation::new(
            "normalize_request",
            "identity_document.endpoints must be a non-empty array",
        ));
    }
    for endpoint in &document.endpoints {
        validate_non_empty("identity_document.endpoints[].protocol", &endpoint.protocol)?;
        validate_non_empty("identity_document.endpoints[].url", &endpoint.url)?;
    }

    if document.created_at >= document.expires_at {
        return Err(Violation::new(
            "normalize_request",
            "identity_document.created_at must be before identity_document.expires_at",
        ));
    }

    if let Some(attestation) = document.attestation.as_ref() {
        validate_non_empty("identity_document.attestation.type", &attestation.type_name)?;
        validate_non_empty("identity_document.attestation.issuer", &attestation.issuer)?;
        validate_non_empty(
            "identity_document.attestation.evidence_ref",
            &attestation.evidence_ref,
        )?;
    }

    Ok(())
}

fn validate_spec_version(field_name: &str, value: &str) -> Result<(), Violation> {
    validate_non_empty(field_name, value)?;
    if !SUPPORTED_SPEC_VERSIONS.contains(&value) {
        let supported = SUPPORTED_SPEC_VERSIONS.join(", ");
        return Err(Violation::new(
            "normalize_request",
            format!(
                "{field_name} specifies unsupported version {value:?}; supported: {supported}"
            ),
        ));
    }
    Ok(())
}

fn validate_kind(field_name: &str, actual: &str, expected: &str) -> Result<(), Violation> {
    validate_non_empty(field_name, actual)?;
    if actual != expected {
        return Err(Violation::new(
            "normalize_request",
            format!("{field_name} must equal {expected}"),
        ));
    }
    Ok(())
}

fn validate_non_empty(field_name: &str, value: &str) -> Result<(), Violation> {
    if value.trim().is_empty() {
        return Err(Violation::new(
            "normalize_request",
            format!("{field_name} must be a non-empty string"),
        ));
    }
    Ok(())
}

fn validate_non_empty_vec(field_name: &str, values: &[String]) -> Result<(), Violation> {
    if values.is_empty() {
        return Err(Violation::new(
            "normalize_request",
            format!("{field_name} must be a non-empty array of strings"),
        ));
    }

    for value in values {
        validate_non_empty(field_name, value)?;
    }
    Ok(())
}

fn validate_runtime_context(envelope: &RequestEnvelope) -> Result<(), Violation> {
    if let Some(requested_spend) = envelope.runtime_context.requested_spend {
        if requested_spend < 0 {
            return Err(Violation::new(
                "normalize_request",
                "request.runtime_context.requested_spend must be zero or positive",
            ));
        }
    }
    if let Some(currency) = envelope.runtime_context.spend_currency.as_ref() {
        validate_non_empty("request.runtime_context.spend_currency", currency)?;
    }
    if let Some(target_email) = envelope.runtime_context.target_email.as_ref() {
        validate_non_empty("request.runtime_context.target_email", target_email)?;
    }
    if let Some(target_calendar_id) = envelope.runtime_context.target_calendar_id.as_ref() {
        validate_non_empty(
            "request.runtime_context.target_calendar_id",
            target_calendar_id,
        )?;
    }
    Ok(())
}
