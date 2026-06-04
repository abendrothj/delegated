use crate::crypto::TOKEN_SIGNATURE_ALG_ED25519;
use crate::models::{AgentIdentityDocument, Violation};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;

pub const DISCOVERY_ISSUER_PATH: &str = "/.well-known/agentauth-issuer";
pub const DISCOVERY_JWKS_PATH: &str = "/.well-known/jwks.json";
pub const DISCOVERY_REGISTRY_PREFIX: &str = "/registry/";
pub const DISCOVERY_RESOLVE_PREFIX: &str = "/resolve/";

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryHttpRequest {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub query: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryHttpResponse {
    pub status_code: u16,
    pub body: Value,
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

pub fn handle_discovery_http_request(
    service: &DiscoveryService,
    request: &DiscoveryHttpRequest,
) -> DiscoveryHttpResponse {
    if request.method != "GET" {
        return discovery_error(
            405,
            "discovery handlers only support GET requests".to_string(),
        );
    }

    if request.path == DISCOVERY_ISSUER_PATH {
        return serve_issuer_metadata(service, &request.query);
    }
    if request.path == DISCOVERY_JWKS_PATH {
        return serve_jwks(service, &request.query);
    }
    if let Some(agent_id) = request.path.strip_prefix(DISCOVERY_REGISTRY_PREFIX) {
        return serve_registry_lookup(service, agent_id);
    }
    if let Some(agent_id) = request.path.strip_prefix(DISCOVERY_RESOLVE_PREFIX) {
        return serve_resolution_lookup(service, agent_id, &request.query);
    }

    discovery_error(404, format!("unknown discovery path: {}", request.path))
}

fn serve_issuer_metadata(
    service: &DiscoveryService,
    query: &HashMap<String, String>,
) -> DiscoveryHttpResponse {
    let issuer = match query.get("issuer") {
        Some(issuer) if !issuer.trim().is_empty() => issuer.clone(),
        Some(_) => {
            return discovery_error(400, "query parameter issuer must be non-empty".to_string());
        }
        None => {
            if service.issuer_metadata.len() == 1 {
                service
                    .issuer_metadata
                    .keys()
                    .next()
                    .cloned()
                    .expect("issuer metadata length checked to be one")
            } else {
                return discovery_error(
                    400,
                    "query parameter issuer is required when multiple issuers are registered"
                        .to_string(),
                );
            }
        }
    };
    match service.get_issuer_metadata(&issuer) {
        Some(metadata) => discovery_ok(
            200,
            serde_json::to_value(metadata).expect("serialize metadata"),
        ),
        None => discovery_error(
            404,
            format!("issuer metadata not found for issuer: {issuer}"),
        ),
    }
}

fn serve_jwks(
    service: &DiscoveryService,
    query: &HashMap<String, String>,
) -> DiscoveryHttpResponse {
    let agent_id = match query.get("agent_id") {
        Some(agent_id) if !agent_id.trim().is_empty() => agent_id,
        Some(_) => {
            return discovery_error(
                400,
                "query parameter agent_id must be non-empty".to_string(),
            );
        }
        None => {
            return discovery_error(400, "query parameter agent_id is required".to_string());
        }
    };
    let identity_document = match service.get_identity_document(agent_id) {
        Some(document) => document,
        None => {
            return discovery_error(
                404,
                format!("identity document not found for agent_id: {agent_id}"),
            );
        }
    };
    match build_jwks_document(identity_document) {
        Ok(jwks) => discovery_ok(200, serde_json::to_value(jwks).expect("serialize jwks")),
        Err(error) => discovery_error(422, error.reason),
    }
}

fn serve_registry_lookup(service: &DiscoveryService, agent_id: &str) -> DiscoveryHttpResponse {
    if agent_id.trim().is_empty() {
        return discovery_error(400, "registry path must include agent_id".to_string());
    }
    match service.get_identity_document(agent_id) {
        Some(document) => discovery_ok(
            200,
            serde_json::to_value(document).expect("serialize identity document"),
        ),
        None => discovery_error(
            404,
            format!("identity document not found for agent_id: {agent_id}"),
        ),
    }
}

fn serve_resolution_lookup(
    service: &DiscoveryService,
    agent_id: &str,
    query: &HashMap<String, String>,
) -> DiscoveryHttpResponse {
    if agent_id.trim().is_empty() {
        return discovery_error(400, "resolution path must include agent_id".to_string());
    }
    let protocol = match query.get("protocol") {
        Some(protocol) if !protocol.trim().is_empty() => protocol,
        Some(_) => {
            return discovery_error(
                400,
                "query parameter protocol must be non-empty".to_string(),
            );
        }
        None => {
            return discovery_error(400, "query parameter protocol is required".to_string());
        }
    };
    match service.resolve_agent_endpoint(agent_id, protocol) {
        Some(endpoint) => discovery_ok(
            200,
            json!({
                "agent_id": agent_id,
                "protocol": protocol,
                "endpoint": endpoint
            }),
        ),
        None => discovery_error(
            404,
            format!("endpoint not found for agent_id {agent_id} and protocol {protocol}"),
        ),
    }
}

fn discovery_ok(status_code: u16, body: Value) -> DiscoveryHttpResponse {
    DiscoveryHttpResponse { status_code, body }
}

fn discovery_error(status_code: u16, message: String) -> DiscoveryHttpResponse {
    DiscoveryHttpResponse {
        status_code,
        body: json!({ "error": message }),
    }
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

    fn issuer_metadata() -> IssuerMetadata {
        IssuerMetadata {
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
        }
    }

    fn seeded_discovery_service() -> DiscoveryService {
        let mut service = DiscoveryService::new();
        service.register_issuer_metadata(issuer_metadata());
        service.register_identity_document(identity_document());
        service
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
        let service = seeded_discovery_service();
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

    #[test]
    fn serves_canonical_discovery_paths() {
        let service = seeded_discovery_service();

        let issuer_response = handle_discovery_http_request(
            &service,
            &DiscoveryHttpRequest {
                method: "GET".to_string(),
                path: DISCOVERY_ISSUER_PATH.to_string(),
                query: HashMap::new(),
            },
        );
        assert_eq!(issuer_response.status_code, 200);
        assert_eq!(
            issuer_response.body["issuer"],
            json!("https://trust.example.ai")
        );

        let mut jwks_query = HashMap::new();
        jwks_query.insert(
            "agent_id".to_string(),
            "agent:example:scheduler:v1".to_string(),
        );
        let jwks_response = handle_discovery_http_request(
            &service,
            &DiscoveryHttpRequest {
                method: "GET".to_string(),
                path: DISCOVERY_JWKS_PATH.to_string(),
                query: jwks_query,
            },
        );
        assert_eq!(jwks_response.status_code, 200);
        assert_eq!(jwks_response.body["keys"][0]["alg"], json!("EdDSA"));

        let registry_response = handle_discovery_http_request(
            &service,
            &DiscoveryHttpRequest {
                method: "GET".to_string(),
                path: "/registry/agent:example:scheduler:v1".to_string(),
                query: HashMap::new(),
            },
        );
        assert_eq!(registry_response.status_code, 200);
        assert_eq!(
            registry_response.body["agent_id"],
            json!("agent:example:scheduler:v1")
        );

        let mut resolve_query = HashMap::new();
        resolve_query.insert("protocol".to_string(), "mcp".to_string());
        let resolve_response = handle_discovery_http_request(
            &service,
            &DiscoveryHttpRequest {
                method: "GET".to_string(),
                path: "/resolve/agent:example:scheduler:v1".to_string(),
                query: resolve_query,
            },
        );
        assert_eq!(resolve_response.status_code, 200);
        assert_eq!(
            resolve_response.body["endpoint"],
            json!("https://agents.example.ai/scheduler/mcp")
        );
    }

    #[test]
    fn rejects_invalid_discovery_requests() {
        let service = seeded_discovery_service();
        let wrong_method = handle_discovery_http_request(
            &service,
            &DiscoveryHttpRequest {
                method: "POST".to_string(),
                path: DISCOVERY_ISSUER_PATH.to_string(),
                query: HashMap::new(),
            },
        );
        assert_eq!(wrong_method.status_code, 405);

        let missing_jwks_query = handle_discovery_http_request(
            &service,
            &DiscoveryHttpRequest {
                method: "GET".to_string(),
                path: DISCOVERY_JWKS_PATH.to_string(),
                query: HashMap::new(),
            },
        );
        assert_eq!(missing_jwks_query.status_code, 400);

        let not_found = handle_discovery_http_request(
            &service,
            &DiscoveryHttpRequest {
                method: "GET".to_string(),
                path: "/resolve/agent:example:scheduler:v1".to_string(),
                query: HashMap::new(),
            },
        );
        assert_eq!(not_found.status_code, 400);
    }
}
