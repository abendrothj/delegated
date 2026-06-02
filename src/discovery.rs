use crate::crypto::TOKEN_SIGNATURE_ALG_ED25519;
use crate::models::{AgentIdentityDocument, Violation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerMetadata {
    pub issuer: String,
    pub jwks_uri: String,
    pub registry_uri: String,
    pub resolution_uri: String,
    pub revocation_uri: String,
    pub approval_uri: String,
    pub supported_signature_algorithms: Vec<String>,
    pub supported_protocols: Vec<String>,
    pub supported_profiles: Vec<String>,
    pub spec_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwksDocument {
    pub keys: Vec<JwkRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwkRecord {
    pub kid: String,
    pub kty: String,
    pub crv: String,
    pub x: String,
    #[serde(rename = "use")]
    pub use_field: String,
    pub alg: String,
}

#[derive(Debug, Clone, Default)]
pub struct DiscoveryService {
    issuer_metadata: HashMap<String, IssuerMetadata>,
    registry: HashMap<String, AgentIdentityDocument>,
}

impl DiscoveryService {
    pub fn new() -> Self {
        Self {
            issuer_metadata: HashMap::new(),
            registry: HashMap::new(),
        }
    }

    pub fn register_issuer_metadata(&mut self, metadata: IssuerMetadata) {
        self.issuer_metadata
            .insert(metadata.issuer.clone(), metadata);
    }

    pub fn register_identity_document(&mut self, document: AgentIdentityDocument) {
        self.registry.insert(document.agent_id.clone(), document);
    }

    pub fn get_issuer_metadata(&self, issuer: &str) -> Option<&IssuerMetadata> {
        self.issuer_metadata.get(issuer)
    }

    pub fn get_identity_document(&self, agent_id: &str) -> Option<&AgentIdentityDocument> {
        self.registry.get(agent_id)
    }

    pub fn resolve_agent_endpoint(&self, agent_id: &str, protocol: &str) -> Option<String> {
        self.registry.get(agent_id).and_then(|document| {
            document
                .endpoints
                .iter()
                .find(|endpoint| endpoint.protocol == protocol)
                .map(|endpoint| endpoint.url.clone())
        })
    }
}

pub fn build_jwks_document(
    identity_document: &AgentIdentityDocument,
) -> Result<JwksDocument, Violation> {
    let mut keys = Vec::with_capacity(identity_document.public_keys.len());
    for key in &identity_document.public_keys {
        let crv = key.crv.clone().ok_or_else(|| {
            Violation::new(
                "build_jwks_document",
                "identity public key must include crv for JWKS conversion",
            )
        })?;
        let x = key.x.clone().ok_or_else(|| {
            Violation::new(
                "build_jwks_document",
                "identity public key must include x for JWKS conversion",
            )
        })?;
        if key.kty != "OKP" || crv != TOKEN_SIGNATURE_ALG_ED25519 {
            return Err(Violation::new(
                "build_jwks_document",
                "only OKP/Ed25519 keys are supported in JWKS conversion",
            ));
        }
        keys.push(JwkRecord {
            kid: key.kid.clone(),
            kty: key.kty.clone(),
            crv,
            x,
            use_field: "sig".to_string(),
            alg: "EdDSA".to_string(),
        });
    }
    Ok(JwksDocument { keys })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AgentEndpoint, AgentIdentityDocument, PublicKeyRecord};
    use chrono::{TimeZone, Utc};

    fn identity_document() -> AgentIdentityDocument {
        AgentIdentityDocument {
            spec_version: "0.1".to_string(),
            kind: "AgentIdentityDocument".to_string(),
            agent_id: "agent:example:scheduler:v1".to_string(),
            display_name: Some("Scheduler".to_string()),
            owner_id: "org:example".to_string(),
            issuer: "https://trust.example.ai".to_string(),
            identity_type: "spiffe".to_string(),
            subject: "spiffe://example.ai/agents/scheduler".to_string(),
            public_keys: vec![PublicKeyRecord {
                kid: "key-2026-01".to_string(),
                kty: "OKP".to_string(),
                crv: Some(TOKEN_SIGNATURE_ALG_ED25519.to_string()),
                x: Some("abc".to_string()),
            }],
            supported_protocols: vec!["http".to_string(), "mcp".to_string()],
            supported_auth_methods: vec!["delegation_token".to_string()],
            capabilities: None,
            endpoints: vec![AgentEndpoint {
                protocol: "mcp".to_string(),
                url: "https://agents.example.ai/scheduler/mcp".to_string(),
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
        }
    }

    #[test]
    fn builds_rfc_style_jwks_document() {
        let jwks = build_jwks_document(&identity_document()).expect("JWKS conversion should work");
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].use_field, "sig");
        assert_eq!(jwks.keys[0].alg, "EdDSA");
    }

    #[test]
    fn resolves_registered_agent_endpoint() {
        let mut service = DiscoveryService::new();
        let metadata = IssuerMetadata {
            issuer: "https://trust.example.ai".to_string(),
            jwks_uri: "https://trust.example.ai/.well-known/jwks.json".to_string(),
            registry_uri: "https://trust.example.ai/registry".to_string(),
            resolution_uri: "https://trust.example.ai/resolve".to_string(),
            revocation_uri: "https://trust.example.ai/revoke".to_string(),
            approval_uri: "https://trust.example.ai/approve".to_string(),
            supported_signature_algorithms: vec!["Ed25519".to_string()],
            supported_protocols: vec!["http".to_string(), "mcp".to_string()],
            supported_profiles: vec!["developer".to_string(), "spiffe".to_string()],
            spec_version: "0.1".to_string(),
        };
        service.register_issuer_metadata(metadata);
        service.register_identity_document(identity_document());
        assert_eq!(
            service.resolve_agent_endpoint("agent:example:scheduler:v1", "mcp"),
            Some("https://agents.example.ai/scheduler/mcp".to_string())
        );
        assert!(
            service
                .get_issuer_metadata("https://trust.example.ai")
                .is_some()
        );
    }
}
