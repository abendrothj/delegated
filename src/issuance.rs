use crate::contracts::SPEC_VERSION_CURRENT;
use crate::crypto::{
    TOKEN_SIGNATURE_ALG_ED25519, sign_delegation_token, sign_identity_document,
};
use crate::models::{
    AgentEndpoint, AgentIdentityDocument, DelegationToken, MaxSpend, PublicKeyRecord,
    RequestEnvelope, ResourceConstraints, RuntimeContext, TrustProfile,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::SigningKey;
use std::sync::atomic::{AtomicU64, Ordering};

static ISSUANCE_COUNTER: AtomicU64 = AtomicU64::new(1);

fn unique_suffix() -> String {
    let counter = ISSUANCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock should be after epoch")
        .as_nanos();
    format!("{counter}_{nanos}")
}

/// Error returned when a required field is missing or a constraint is violated
/// during issuance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuanceError {
    pub field: &'static str,
    pub reason: &'static str,
}

impl IssuanceError {
    fn missing(field: &'static str) -> Self {
        Self {
            field,
            reason: "required field is missing",
        }
    }

    fn invalid(field: &'static str, reason: &'static str) -> Self {
        Self { field, reason }
    }
}

impl std::fmt::Display for IssuanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.reason)
    }
}

impl std::error::Error for IssuanceError {}

// ─── DelegationTokenBuilder ──────────────────────────────────────────────────

/// Fluent builder for [`DelegationToken`].
///
/// Required fields: `issuer`, `agent_id`, `delegator_id`, `owner_id`,
/// `key_id`, at least one audience, and at least one allowed action.
/// `issued_at` defaults to now. `expires_at` must be set explicitly or via
/// `expires_in` (relative to `issued_at`). A unique `token_id` and `nonce`
/// are generated automatically if not provided.
///
/// # Example
/// ```rust,no_run
/// # use delegated::issuance::DelegationTokenBuilder;
/// # use ed25519_dalek::SigningKey;
/// # let key = SigningKey::from_bytes(&[1u8; 32]);
/// let token = DelegationTokenBuilder::new()
///     .issuer("https://trust.example.ai")
///     .agent_id("agent:example:scheduler:v1")
///     .delegator_id("user:alice")
///     .owner_id("org:example")
///     .audience("tool:google-calendar")
///     .allowed_action("calendar.create_event")
///     .key_id("key-2026-01")
///     .expires_in(chrono::Duration::hours(1))
///     .build_and_sign(&key)
///     .expect("token issuance failed");
/// ```
#[derive(Default)]
pub struct DelegationTokenBuilder {
    token_id: Option<String>,
    issuer: Option<String>,
    agent_id: Option<String>,
    delegator_id: Option<String>,
    owner_id: Option<String>,
    audience: Vec<String>,
    allowed_actions: Vec<String>,
    resource_constraints: Option<ResourceConstraints>,
    max_spend: Option<MaxSpend>,
    max_delegation_depth: Option<u16>,
    issued_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    expires_in: Option<Duration>,
    intent: Option<String>,
    nonce: Option<String>,
    key_id: Option<String>,
}

impl DelegationTokenBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn token_id(mut self, id: impl Into<String>) -> Self {
        self.token_id = Some(id.into());
        self
    }

    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    pub fn agent_id(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = Some(agent_id.into());
        self
    }

    pub fn delegator_id(mut self, delegator_id: impl Into<String>) -> Self {
        self.delegator_id = Some(delegator_id.into());
        self
    }

    pub fn owner_id(mut self, owner_id: impl Into<String>) -> Self {
        self.owner_id = Some(owner_id.into());
        self
    }

    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience.push(audience.into());
        self
    }

    pub fn audiences(mut self, audiences: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.audience.extend(audiences.into_iter().map(Into::into));
        self
    }

    pub fn allowed_action(mut self, action: impl Into<String>) -> Self {
        self.allowed_actions.push(action.into());
        self
    }

    pub fn allowed_actions(
        mut self,
        actions: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.allowed_actions
            .extend(actions.into_iter().map(Into::into));
        self
    }

    pub fn resource_constraints(mut self, constraints: ResourceConstraints) -> Self {
        self.resource_constraints = Some(constraints);
        self
    }

    pub fn max_spend(mut self, amount: i64, currency: impl Into<String>) -> Self {
        self.max_spend = Some(MaxSpend {
            amount,
            currency: currency.into(),
        });
        self
    }

    pub fn max_delegation_depth(mut self, depth: u16) -> Self {
        self.max_delegation_depth = Some(depth);
        self
    }

    pub fn issued_at(mut self, ts: DateTime<Utc>) -> Self {
        self.issued_at = Some(ts);
        self
    }

    pub fn expires_at(mut self, ts: DateTime<Utc>) -> Self {
        self.expires_at = Some(ts);
        self
    }

    /// Set expiry relative to `issued_at` (or now if `issued_at` is not set).
    pub fn expires_in(mut self, duration: Duration) -> Self {
        self.expires_in = Some(duration);
        self
    }

    pub fn intent(mut self, intent: impl Into<String>) -> Self {
        self.intent = Some(intent.into());
        self
    }

    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    pub fn key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    pub fn build_and_sign(self, signing_key: &SigningKey) -> Result<DelegationToken, IssuanceError> {
        let issuer = self.issuer.ok_or_else(|| IssuanceError::missing("issuer"))?;
        let agent_id = self
            .agent_id
            .ok_or_else(|| IssuanceError::missing("agent_id"))?;
        let delegator_id = self
            .delegator_id
            .ok_or_else(|| IssuanceError::missing("delegator_id"))?;
        let owner_id = self
            .owner_id
            .ok_or_else(|| IssuanceError::missing("owner_id"))?;
        let key_id = self
            .key_id
            .ok_or_else(|| IssuanceError::missing("key_id"))?;

        if self.audience.is_empty() {
            return Err(IssuanceError::invalid(
                "audience",
                "at least one audience is required",
            ));
        }
        if self.allowed_actions.is_empty() {
            return Err(IssuanceError::invalid(
                "allowed_actions",
                "at least one allowed action is required",
            ));
        }

        let issued_at = self.issued_at.unwrap_or_else(Utc::now);
        let expires_at = match (self.expires_at, self.expires_in) {
            (Some(ts), _) => ts,
            (None, Some(dur)) => issued_at + dur,
            (None, None) => {
                return Err(IssuanceError::missing("expires_at or expires_in"));
            }
        };

        if expires_at <= issued_at {
            return Err(IssuanceError::invalid(
                "expires_at",
                "expires_at must be after issued_at",
            ));
        }

        let suffix = unique_suffix();
        let mut token = DelegationToken {
            spec_version: SPEC_VERSION_CURRENT.to_string(),
            kind: "DelegationToken".to_string(),
            token_id: self
                .token_id
                .unwrap_or_else(|| format!("dlg_{suffix}")),
            issuer,
            agent_id,
            delegator_id,
            owner_id,
            audience: self.audience,
            allowed_actions: self.allowed_actions,
            resource_constraints: self.resource_constraints,
            max_spend: self.max_spend,
            max_delegation_depth: self.max_delegation_depth,
            issued_at,
            expires_at,
            intent: self.intent,
            nonce: self
                .nonce
                .unwrap_or_else(|| format!("nonce_{suffix}")),
            key_id,
            signature_alg: TOKEN_SIGNATURE_ALG_ED25519.to_string(),
            signature: String::new(),
        };

        token.signature = sign_delegation_token(&token, signing_key)
            .map_err(|v| IssuanceError::invalid("signature", Box::leak(v.reason.into_boxed_str())))?;

        Ok(token)
    }
}

// ─── AgentIdentityDocumentBuilder ────────────────────────────────────────────

/// Fluent builder for [`AgentIdentityDocument`].
///
/// Required fields: `agent_id`, `owner_id`, `issuer`, `identity_type`,
/// `subject`. The public key record is derived from the signing key passed to
/// `build_and_sign` — you only need to supply the `key_id`. Defaults:
/// `spec_version = "0.1"`, `kind = "AgentIdentityDocument"`,
/// `created_at = now()`, `expires_at = now() + 7 days`.
///
/// # Example
/// ```rust,no_run
/// # use delegated::issuance::AgentIdentityDocumentBuilder;
/// # use ed25519_dalek::SigningKey;
/// # let key = SigningKey::from_bytes(&[1u8; 32]);
/// let doc = AgentIdentityDocumentBuilder::new()
///     .agent_id("agent:example:scheduler:v1")
///     .owner_id("org:example")
///     .issuer("https://trust.example.ai")
///     .identity_type("spiffe")
///     .subject("spiffe://example.ai/agents/scheduler")
///     .key_id("key-2026-01")
///     .supported_protocol("http")
///     .supported_auth_method("delegation_token")
///     .endpoint("http", "https://agents.example.ai/scheduler")
///     .expires_in(chrono::Duration::days(7))
///     .build_and_sign(&key)
///     .expect("document issuance failed");
/// ```
#[derive(Default)]
pub struct AgentIdentityDocumentBuilder {
    agent_id: Option<String>,
    display_name: Option<String>,
    owner_id: Option<String>,
    issuer: Option<String>,
    identity_type: Option<String>,
    subject: Option<String>,
    key_id: Option<String>,
    supported_protocols: Vec<String>,
    supported_auth_methods: Vec<String>,
    capabilities: Option<Vec<String>>,
    endpoints: Vec<AgentEndpoint>,
    created_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    expires_in: Option<Duration>,
}

impl AgentIdentityDocumentBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn agent_id(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = Some(agent_id.into());
        self
    }

    pub fn display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }

    pub fn owner_id(mut self, owner_id: impl Into<String>) -> Self {
        self.owner_id = Some(owner_id.into());
        self
    }

    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    pub fn identity_type(mut self, identity_type: impl Into<String>) -> Self {
        self.identity_type = Some(identity_type.into());
        self
    }

    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    pub fn key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    pub fn supported_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.supported_protocols.push(protocol.into());
        self
    }

    pub fn supported_auth_method(mut self, method: impl Into<String>) -> Self {
        self.supported_auth_methods.push(method.into());
        self
    }

    pub fn capability(mut self, cap: impl Into<String>) -> Self {
        self.capabilities.get_or_insert_with(Vec::new).push(cap.into());
        self
    }

    pub fn endpoint(mut self, protocol: impl Into<String>, url: impl Into<String>) -> Self {
        self.endpoints.push(AgentEndpoint {
            protocol: protocol.into(),
            url: url.into(),
        });
        self
    }

    pub fn created_at(mut self, ts: DateTime<Utc>) -> Self {
        self.created_at = Some(ts);
        self
    }

    pub fn expires_at(mut self, ts: DateTime<Utc>) -> Self {
        self.expires_at = Some(ts);
        self
    }

    pub fn expires_in(mut self, duration: Duration) -> Self {
        self.expires_in = Some(duration);
        self
    }

    pub fn build_and_sign(
        self,
        signing_key: &SigningKey,
    ) -> Result<AgentIdentityDocument, IssuanceError> {
        let agent_id = self
            .agent_id
            .ok_or_else(|| IssuanceError::missing("agent_id"))?;
        let owner_id = self
            .owner_id
            .ok_or_else(|| IssuanceError::missing("owner_id"))?;
        let issuer = self.issuer.ok_or_else(|| IssuanceError::missing("issuer"))?;
        let identity_type = self
            .identity_type
            .ok_or_else(|| IssuanceError::missing("identity_type"))?;
        let subject = self
            .subject
            .ok_or_else(|| IssuanceError::missing("subject"))?;
        let key_id = self
            .key_id
            .ok_or_else(|| IssuanceError::missing("key_id"))?;

        let created_at = self.created_at.unwrap_or_else(Utc::now);
        let expires_at = match (self.expires_at, self.expires_in) {
            (Some(ts), _) => ts,
            (None, Some(dur)) => created_at + dur,
            (None, None) => created_at + Duration::days(7),
        };

        if expires_at <= created_at {
            return Err(IssuanceError::invalid(
                "expires_at",
                "expires_at must be after created_at",
            ));
        }

        let verifying_bytes = signing_key.verifying_key().to_bytes();
        let public_keys = vec![PublicKeyRecord {
            kid: key_id,
            kty: "OKP".to_string(),
            crv: Some(TOKEN_SIGNATURE_ALG_ED25519.to_string()),
            x: Some(Base64UrlUnpadded::encode_string(&verifying_bytes)),
        }];

        let mut doc = AgentIdentityDocument {
            spec_version: SPEC_VERSION_CURRENT.to_string(),
            kind: "AgentIdentityDocument".to_string(),
            agent_id,
            display_name: self.display_name,
            owner_id,
            issuer,
            identity_type,
            subject,
            public_keys,
            supported_protocols: self.supported_protocols,
            supported_auth_methods: self.supported_auth_methods,
            capabilities: self.capabilities,
            endpoints: self.endpoints,
            attestation: None,
            created_at,
            expires_at,
            signature: String::new(),
        };

        doc.signature = sign_identity_document(&doc, signing_key)
            .map_err(|v| IssuanceError::invalid("signature", Box::leak(v.reason.into_boxed_str())))?;

        Ok(doc)
    }
}

// ─── RequestEnvelopeBuilder ───────────────────────────────────────────────────

/// Assembles a [`RequestEnvelope`] from a signed identity document and token.
///
/// Required fields: `identity_document`, `token`, `audience`, `action`.
/// `agent_id` and `delegator_id` default to the values in `token`.
/// A unique `request_id` is generated automatically if not provided.
///
/// # Example
/// ```rust,no_run
/// # use delegated::issuance::{RequestEnvelopeBuilder, AgentIdentityDocumentBuilder, DelegationTokenBuilder};
/// # use ed25519_dalek::SigningKey;
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
///     .build()
///     .expect("envelope assembly failed");
/// ```
#[derive(Default)]
pub struct RequestEnvelopeBuilder {
    request_id: Option<String>,
    profile: Option<TrustProfile>,
    agent_id: Option<String>,
    delegator_id: Option<String>,
    audience: Option<String>,
    action: Option<String>,
    resource: Option<String>,
    runtime_context: Option<RuntimeContext>,
    identity_document: Option<AgentIdentityDocument>,
    token: Option<DelegationToken>,
}

impl RequestEnvelopeBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    pub fn profile(mut self, profile: TrustProfile) -> Self {
        self.profile = Some(profile);
        self
    }

    pub fn agent_id(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = Some(agent_id.into());
        self
    }

    pub fn delegator_id(mut self, delegator_id: impl Into<String>) -> Self {
        self.delegator_id = Some(delegator_id.into());
        self
    }

    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    pub fn action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }

    pub fn resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    pub fn runtime_context(mut self, ctx: RuntimeContext) -> Self {
        self.runtime_context = Some(ctx);
        self
    }

    pub fn identity_document(mut self, doc: AgentIdentityDocument) -> Self {
        self.identity_document = Some(doc);
        self
    }

    pub fn token(mut self, token: DelegationToken) -> Self {
        self.token = Some(token);
        self
    }

    pub fn build(self) -> Result<RequestEnvelope, IssuanceError> {
        let token = self
            .token
            .ok_or_else(|| IssuanceError::missing("token"))?;
        let audience = self
            .audience
            .ok_or_else(|| IssuanceError::missing("audience"))?;
        let action = self
            .action
            .ok_or_else(|| IssuanceError::missing("action"))?;

        let agent_id = self.agent_id.unwrap_or_else(|| token.agent_id.clone());
        let delegator_id = self
            .delegator_id
            .unwrap_or_else(|| token.delegator_id.clone());

        Ok(RequestEnvelope {
            spec_version: SPEC_VERSION_CURRENT.to_string(),
            kind: "TrustRequestEnvelope".to_string(),
            request_id: Some(
                self.request_id
                    .unwrap_or_else(|| format!("req_{}", unique_suffix())),
            ),
            profile: self.profile.unwrap_or_default(),
            agent_id,
            delegator_id,
            audience,
            action,
            resource: self.resource,
            runtime_context: self.runtime_context.unwrap_or_default(),
            identity_document: self.identity_document,
            token,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::evaluate_request;
    use crate::revocation::InMemoryTrustState;
    use crate::engine::evaluate_request_with_state;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[88u8; 32])
    }

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    #[test]
    fn builds_and_signs_delegation_token() {
        let token = DelegationTokenBuilder::new()
            .issuer("https://trust.example.ai")
            .agent_id("agent:example:scheduler:v1")
            .delegator_id("user:alice")
            .owner_id("org:example")
            .audience("tool:google-calendar")
            .allowed_action("calendar.create_event")
            .key_id("key-2026-01")
            .expires_in(Duration::hours(1))
            .build_and_sign(&key())
            .expect("token build should succeed");

        assert_eq!(token.spec_version, "0.1");
        assert_eq!(token.kind, "DelegationToken");
        assert!(!token.signature.is_empty());
        assert!(!token.token_id.is_empty());
        assert!(!token.nonce.is_empty());
        assert!(token.expires_at > token.issued_at);
    }

    #[test]
    fn token_builder_rejects_missing_required_fields() {
        let err = DelegationTokenBuilder::new()
            .issuer("https://trust.example.ai")
            .build_and_sign(&key())
            .expect_err("missing required fields should fail");
        assert_eq!(err.field, "agent_id");

        let err = DelegationTokenBuilder::new()
            .issuer("https://trust.example.ai")
            .agent_id("agent:example:scheduler:v1")
            .delegator_id("user:alice")
            .owner_id("org:example")
            .key_id("key-2026-01")
            .expires_in(Duration::hours(1))
            .build_and_sign(&key())
            .expect_err("missing audience should fail");
        assert_eq!(err.field, "audience");
    }

    #[test]
    fn builds_and_signs_identity_document() {
        let doc = AgentIdentityDocumentBuilder::new()
            .agent_id("agent:example:scheduler:v1")
            .owner_id("org:example")
            .issuer("https://trust.example.ai")
            .identity_type("spiffe")
            .subject("spiffe://example.ai/agents/scheduler")
            .key_id("key-2026-01")
            .supported_protocol("http")
            .supported_auth_method("delegation_token")
            .endpoint("http", "https://agents.example.ai/scheduler")
            .expires_in(Duration::days(7))
            .build_and_sign(&key())
            .expect("document build should succeed");

        assert_eq!(doc.spec_version, "0.1");
        assert_eq!(doc.kind, "AgentIdentityDocument");
        assert!(!doc.signature.is_empty());
        assert_eq!(doc.public_keys.len(), 1);
        assert_eq!(doc.public_keys[0].kid, "key-2026-01");
    }

    #[test]
    fn full_issuance_pipeline_produces_evaluatable_request() {
        let k = key();
        let doc = AgentIdentityDocumentBuilder::new()
            .agent_id("agent:example:scheduler:v1")
            .owner_id("org:example")
            .issuer("https://trust.example.ai")
            .identity_type("spiffe")
            .subject("spiffe://example.ai/agents/scheduler")
            .key_id("key-2026-01")
            .supported_protocol("http")
            .supported_auth_method("delegation_token")
            .endpoint("http", "https://agents.example.ai/scheduler")
            .build_and_sign(&k)
            .expect("document issuance should succeed");

        let token = DelegationTokenBuilder::new()
            .issuer("https://trust.example.ai")
            .agent_id("agent:example:scheduler:v1")
            .delegator_id("user:alice")
            .owner_id("org:example")
            .audience("tool:google-calendar")
            .allowed_action("calendar.create_event")
            .key_id("key-2026-01")
            .expires_in(Duration::hours(1))
            .build_and_sign(&k)
            .expect("token issuance should succeed");

        let envelope = RequestEnvelopeBuilder::new()
            .identity_document(doc)
            .token(token)
            .audience("tool:google-calendar")
            .action("calendar.create_event")
            .build()
            .expect("envelope build should succeed");

        let raw = serde_json::to_value(envelope).expect("serialization should succeed");
        let mut state = InMemoryTrustState::new();
        let (decision, _) = evaluate_request_with_state(&raw, now(), &mut state, &crate::models::HostContext::default());
        assert!(decision.allowed, "unexpected deny: {}", decision.reason);
    }
}
