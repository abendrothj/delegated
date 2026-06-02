use crate::models::{RequestEnvelope, TrustProfile, Violation};

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
            Ok(envelope)
        }
    }
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
}
