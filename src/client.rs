use crate::adapters::a2a::{A2aProtocolRequest, A2aProtocolResponse};
use crate::adapters::mcp::McpJsonRpcResponse;
use crate::models::RequestEnvelope;
use crate::wire::{SHARED_CLAIMS_KIND, SharedTrustClaims};
use serde_json::{Value, json};
use std::fmt;

/// Errors returned by the delegated HTTP client.
#[derive(Debug)]
pub struct ClientError {
    pub kind: ClientErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientErrorKind {
    /// The underlying HTTP transport failed (connection refused, timeout, TLS, etc.).
    Network,
    /// The request envelope could not be serialized.
    Serialization,
    /// The server responded but the body could not be parsed as the expected format.
    InvalidResponse,
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for ClientError {}

impl ClientError {
    fn network(e: impl fmt::Display) -> Self {
        Self {
            kind: ClientErrorKind::Network,
            message: e.to_string(),
        }
    }
    fn serialization(e: impl fmt::Display) -> Self {
        Self {
            kind: ClientErrorKind::Serialization,
            message: e.to_string(),
        }
    }
    fn invalid_response(e: impl fmt::Display) -> Self {
        Self {
            kind: ClientErrorKind::InvalidResponse,
            message: e.to_string(),
        }
    }
}

/// The parsed response from a delegated HTTP trust endpoint.
#[derive(Debug, Clone)]
pub struct HttpTrustResponse {
    pub status_code: u16,
    pub allowed: bool,
    pub stage: String,
    pub reason: String,
}

impl HttpTrustResponse {
    /// Returns `true` if the server allowed the request.
    pub fn is_allowed(&self) -> bool {
        self.allowed
    }
}

/// The parsed response from a delegated MCP trust endpoint.
#[derive(Debug, Clone)]
pub struct McpTrustResponse {
    pub status_code: u16,
    pub response: McpJsonRpcResponse,
}

impl McpTrustResponse {
    pub fn is_allowed(&self) -> bool {
        self.response.error.is_none()
    }
}

/// The parsed response from a delegated A2A trust endpoint.
#[derive(Debug, Clone)]
pub struct A2aTrustResponse {
    pub status_code: u16,
    pub response: A2aProtocolResponse,
}

impl A2aTrustResponse {
    pub fn is_allowed(&self) -> bool {
        self.response.status == "ok"
    }
}

/// HTTP client for sending trust-validated requests to services that run the
/// `delegated` server-side adapters.
///
/// Build a [`RequestEnvelope`] using the issuance builders, then use this
/// client to send it to the remote service. The client handles serialization,
/// transport, and response parsing.
///
/// # Example
/// ```rust,no_run
/// # use delegated::client::DelegatedClient;
/// # use delegated::issuance::{AgentIdentityDocumentBuilder, DelegationTokenBuilder, RequestEnvelopeBuilder};
/// # use ed25519_dalek::SigningKey;
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let key = SigningKey::from_bytes(&[1u8; 32]);
/// # let doc = AgentIdentityDocumentBuilder::new()
/// #     .agent_id("agent:example:scheduler:v1").owner_id("org:example")
/// #     .issuer("https://trust.example.ai").identity_type("spiffe")
/// #     .subject("spiffe://example.ai/agents/scheduler").key_id("key-2026-01")
/// #     .supported_protocol("http").supported_auth_method("delegation_token")
/// #     .endpoint("http", "https://agents.example.ai/scheduler")
/// #     .build_and_sign(&key).unwrap();
/// # let token = DelegationTokenBuilder::new()
/// #     .issuer("https://trust.example.ai").agent_id("agent:example:scheduler:v1")
/// #     .delegator_id("user:alice").owner_id("org:example")
/// #     .audience("tool:google-calendar").allowed_action("calendar.create_event")
/// #     .key_id("key-2026-01").expires_in(chrono::Duration::hours(1))
/// #     .build_and_sign(&key).unwrap();
/// let envelope = RequestEnvelopeBuilder::new()
///     .identity_document(doc)
///     .token(token)
///     .audience("tool:google-calendar")
///     .action("calendar.create_event")
///     .build()?;
///
/// let client = DelegatedClient::new();
/// let response = client.evaluate_http("https://api.example.com/trust", &envelope).await?;
/// if response.is_allowed() {
///     println!("request authorized at stage {}", response.stage);
/// }
/// # Ok(())
/// # }
/// ```
pub struct DelegatedClient {
    inner: reqwest::Client,
}

impl Default for DelegatedClient {
    fn default() -> Self {
        Self::new()
    }
}

impl DelegatedClient {
    pub fn new() -> Self {
        Self {
            inner: reqwest::Client::new(),
        }
    }

    /// Use an existing `reqwest::Client`, useful for sharing connection pools or
    /// applying custom middleware (timeouts, retries, custom headers).
    pub fn with_client(client: reqwest::Client) -> Self {
        Self { inner: client }
    }

    /// Send a trust request to a service running the delegated HTTP adapter.
    ///
    /// Posts the `RequestEnvelope` as JSON and parses the `allowed/stage/reason`
    /// response body.
    pub async fn evaluate_http(
        &self,
        url: &str,
        envelope: &RequestEnvelope,
    ) -> Result<HttpTrustResponse, ClientError> {
        let resp = self
            .inner
            .post(url)
            .json(envelope)
            .send()
            .await
            .map_err(ClientError::network)?;

        let status_code = resp.status().as_u16();
        let body: Value = resp.json().await.map_err(ClientError::invalid_response)?;

        Ok(HttpTrustResponse {
            status_code,
            allowed: body
                .get("allowed")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            stage: body
                .get("stage")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            reason: body
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        })
    }

    /// Send a trust request to a service running the delegated MCP adapter.
    ///
    /// Wraps the envelope as `params._trust` in a JSON-RPC 2.0 request. Any
    /// additional parameters you want to pass to the remote method go in
    /// `extra_params` (merged with `_trust`).
    pub async fn evaluate_mcp(
        &self,
        url: &str,
        id: impl Into<Value>,
        method: &str,
        extra_params: Value,
        envelope: &RequestEnvelope,
    ) -> Result<McpTrustResponse, ClientError> {
        let claims = SharedTrustClaims {
            spec_version: envelope.spec_version.clone(),
            kind: SHARED_CLAIMS_KIND.to_string(),
            request_id: envelope.request_id.clone(),
            profile: envelope.profile.clone(),
            agent_id: envelope.agent_id.clone(),
            delegator_id: envelope.delegator_id.clone(),
            audience: envelope.audience.clone(),
            action: envelope.action.clone(),
            resource: envelope.resource.clone(),
            runtime_context: envelope.runtime_context.clone(),
            identity_document: envelope.identity_document.clone(),
            token: envelope.token.clone(),
        };

        let trust_value = serde_json::to_value(&claims).map_err(ClientError::serialization)?;

        let mut params = extra_params.as_object().cloned().unwrap_or_default();
        params.insert("_trust".to_string(), trust_value);

        let body = json!({
            "jsonrpc": "2.0",
            "id": id.into(),
            "method": method,
            "params": params
        });

        let resp = self
            .inner
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(ClientError::network)?;

        let status_code = resp.status().as_u16();
        let response: McpJsonRpcResponse =
            resp.json().await.map_err(ClientError::invalid_response)?;

        Ok(McpTrustResponse {
            status_code,
            response,
        })
    }

    /// Send a trust request to a service running the delegated A2A adapter.
    ///
    /// Wraps the envelope as `trust_claims` in an `A2aProtocolRequest`.
    pub async fn evaluate_a2a(
        &self,
        url: &str,
        message_id: impl Into<String>,
        protocol_version: impl Into<String>,
        message_type: impl Into<String>,
        payload: Value,
        envelope: &RequestEnvelope,
    ) -> Result<A2aTrustResponse, ClientError> {
        let claims = SharedTrustClaims {
            spec_version: envelope.spec_version.clone(),
            kind: SHARED_CLAIMS_KIND.to_string(),
            request_id: envelope.request_id.clone(),
            profile: envelope.profile.clone(),
            agent_id: envelope.agent_id.clone(),
            delegator_id: envelope.delegator_id.clone(),
            audience: envelope.audience.clone(),
            action: envelope.action.clone(),
            resource: envelope.resource.clone(),
            runtime_context: envelope.runtime_context.clone(),
            identity_document: envelope.identity_document.clone(),
            token: envelope.token.clone(),
        };

        let request = A2aProtocolRequest {
            message_id: message_id.into(),
            protocol_version: protocol_version.into(),
            message_type: message_type.into(),
            trust_claims: claims,
            payload,
        };

        let resp = self
            .inner
            .post(url)
            .json(&request)
            .send()
            .await
            .map_err(ClientError::network)?;

        let status_code = resp.status().as_u16();
        let response: A2aProtocolResponse =
            resp.json().await.map_err(ClientError::invalid_response)?;

        Ok(A2aTrustResponse {
            status_code,
            response,
        })
    }
}
