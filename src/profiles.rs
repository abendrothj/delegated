use crate::models::{AgentIdentityDocument, RequestEnvelope, TrustProfile, Violation};

pub fn validate_profile_compatibility(
    envelope: RequestEnvelope,
) -> Result<RequestEnvelope, Violation> {
    let identity = envelope.identity_document.as_ref().ok_or_else(|| {
        Violation::new(
            "validate_profile_compatibility",
            "identity_document is required for profile compatibility checks",
        )
    })?;

    match envelope.profile {
        TrustProfile::Developer => Ok(envelope),
        TrustProfile::Oidc => {
            if identity.identity_type != "oidc" {
                return Err(Violation::new(
                    "validate_profile_compatibility",
                    "OIDC profile requires identity_document.identity_type=oidc",
                ));
            }
            if !identity.issuer.starts_with("https://") {
                return Err(Violation::new(
                    "validate_profile_compatibility",
                    "OIDC profile requires HTTPS issuer",
                ));
            }
            if identity.subject.trim().is_empty() {
                return Err(Violation::new(
                    "validate_profile_compatibility",
                    "OIDC profile requires non-empty identity_document.subject",
                ));
            }
            ensure_delegation_auth_method(identity)?;
            Ok(envelope)
        }
        TrustProfile::Spiffe => {
            if identity.identity_type != "spiffe" {
                return Err(Violation::new(
                    "validate_profile_compatibility",
                    "SPIFFE profile requires identity_document.identity_type=spiffe",
                ));
            }
            if !identity.subject.starts_with("spiffe://") {
                return Err(Violation::new(
                    "validate_profile_compatibility",
                    "SPIFFE profile requires identity_document.subject with spiffe:// prefix",
                ));
            }
            ensure_delegation_auth_method(identity)?;
            ensure_supported_transport(identity)?;
            Ok(envelope)
        }
    }
}

fn ensure_delegation_auth_method(identity: &AgentIdentityDocument) -> Result<(), Violation> {
    if identity
        .supported_auth_methods
        .iter()
        .any(|method| method == "delegation_token")
    {
        return Ok(());
    }
    Err(Violation::new(
        "validate_profile_compatibility",
        "profile requires identity_document.supported_auth_methods to include delegation_token",
    ))
}

fn ensure_supported_transport(identity: &AgentIdentityDocument) -> Result<(), Violation> {
    if identity
        .supported_protocols
        .iter()
        .any(|protocol| matches!(protocol.as_str(), "http" | "mcp" | "a2a"))
    {
        return Ok(());
    }
    Err(Violation::new(
        "validate_profile_compatibility",
        "SPIFFE profile requires at least one supported protocol from http|mcp|a2a",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        AgentEndpoint, AgentIdentityDocument, DelegationToken, PublicKeyRecord, RuntimeContext,
    };
    use chrono::{TimeZone, Utc};

    fn request(profile: TrustProfile, identity_type: &str, subject: &str) -> RequestEnvelope {
        RequestEnvelope {
            spec_version: "0.1".to_string(),
            kind: "TrustRequestEnvelope".to_string(),
            request_id: Some("req_profile_1".to_string()),
            profile,
            agent_id: "agent:example:scheduler:v1".to_string(),
            delegator_id: "user:jake-abendroth".to_string(),
            audience: "tool:google-calendar".to_string(),
            action: "calendar.create_event".to_string(),
            resource: None,
            runtime_context: RuntimeContext::default(),
            identity_document: Some(AgentIdentityDocument {
                spec_version: "0.1".to_string(),
                kind: "AgentIdentityDocument".to_string(),
                agent_id: "agent:example:scheduler:v1".to_string(),
                display_name: None,
                owner_id: "org:example".to_string(),
                issuer: "https://trust.example.ai".to_string(),
                identity_type: identity_type.to_string(),
                subject: subject.to_string(),
                public_keys: vec![PublicKeyRecord {
                    kid: "key-1".to_string(),
                    kty: "OKP".to_string(),
                    crv: Some("Ed25519".to_string()),
                    x: Some("abc".to_string()),
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
                    .with_ymd_and_hms(2026, 6, 1, 0, 0, 0)
                    .single()
                    .expect("valid timestamp"),
                expires_at: Utc
                    .with_ymd_and_hms(2026, 6, 8, 0, 0, 0)
                    .single()
                    .expect("valid timestamp"),
                signature: "sig".to_string(),
            }),
            token: DelegationToken {
                spec_version: "0.1".to_string(),
                kind: "DelegationToken".to_string(),
                token_id: "dlg_1".to_string(),
                issuer: "https://trust.example.ai".to_string(),
                agent_id: "agent:example:scheduler:v1".to_string(),
                delegator_id: "user:jake-abendroth".to_string(),
                owner_id: "org:example".to_string(),
                audience: vec!["tool:google-calendar".to_string()],
                allowed_actions: vec!["calendar.create_event".to_string()],
                resource_constraints: None,
                max_spend: None,
                max_delegation_depth: Some(0),
                approval_policy: None,
                issued_at: Utc
                    .with_ymd_and_hms(2026, 6, 1, 20, 10, 0)
                    .single()
                    .expect("valid timestamp"),
                expires_at: Utc
                    .with_ymd_and_hms(2026, 6, 1, 20, 40, 0)
                    .single()
                    .expect("valid timestamp"),
                intent: None,
                nonce: "nonce".to_string(),
                key_id: "key-1".to_string(),
                signature_alg: "Ed25519".to_string(),
                signature: "sig".to_string(),
            },
        }
    }

    #[test]
    fn accepts_spiffe_profile_when_identity_matches() {
        let envelope = request(
            TrustProfile::Spiffe,
            "spiffe",
            "spiffe://example.ai/agents/scheduler",
        );
        assert!(validate_profile_compatibility(envelope).is_ok());
    }

    #[test]
    fn rejects_oidc_profile_when_identity_type_mismatches() {
        let envelope = request(
            TrustProfile::Oidc,
            "spiffe",
            "spiffe://example.ai/agents/scheduler",
        );
        let error = validate_profile_compatibility(envelope).expect_err("should be denied");
        assert_eq!(error.stage, "validate_profile_compatibility");
    }

    #[test]
    fn rejects_oidc_profile_without_delegation_auth_method() {
        let mut envelope = request(TrustProfile::Oidc, "oidc", "service-account-subject");
        envelope
            .identity_document
            .as_mut()
            .expect("identity")
            .supported_auth_methods = vec!["oauth_bearer".to_string()];
        let error = validate_profile_compatibility(envelope).expect_err("should be denied");
        assert_eq!(
            error.reason,
            "profile requires identity_document.supported_auth_methods to include delegation_token"
        );
    }

    #[test]
    fn rejects_spiffe_profile_without_supported_transport() {
        let mut envelope = request(
            TrustProfile::Spiffe,
            "spiffe",
            "spiffe://example.ai/agents/scheduler",
        );
        envelope
            .identity_document
            .as_mut()
            .expect("identity")
            .supported_protocols = vec!["smtp".to_string()];
        let error = validate_profile_compatibility(envelope).expect_err("should be denied");
        assert_eq!(
            error.reason,
            "SPIFFE profile requires at least one supported protocol from http|mcp|a2a"
        );
    }
}
