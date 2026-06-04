use crate::audit::AuditSink;
use crate::engine_async::evaluate_and_audit_with_async_state;
use crate::models::HostContext;
use crate::revocation_async::AsyncTrustStateStore;
use axum::{
    body::Body,
    http::{Request, StatusCode, header::CONTENT_LENGTH},
    response::Response,
};
use chrono::Utc;
use serde_json::json;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{Layer, Service};

const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;

/// Provides a `HostContext` for each incoming request based on the extracted agent and delegator IDs.
pub trait AsyncHostContextProvider: Send + Sync {
    fn provide(&self, agent_id: &str, delegator_id: &str) -> HostContext;
}

/// A [`AsyncHostContextProvider`] that returns the same `HostContext` for every request.
#[derive(Clone)]
pub struct StaticAsyncHostContextProvider {
    context: HostContext,
}

impl StaticAsyncHostContextProvider {
    pub fn new(context: HostContext) -> Self {
        Self { context }
    }
}

impl AsyncHostContextProvider for StaticAsyncHostContextProvider {
    fn provide(&self, _agent_id: &str, _delegator_id: &str) -> HostContext {
        self.context.clone()
    }
}

/// Builder for [`DelegatedLayer`].
pub struct DelegatedLayerBuilder {
    trust_state: Arc<dyn AsyncTrustStateStore>,
    audit_sink: Arc<dyn AuditSink>,
    host_context_provider: Arc<dyn AsyncHostContextProvider>,
    max_body_bytes: usize,
}

impl DelegatedLayerBuilder {
    pub fn new(trust_state: Arc<dyn AsyncTrustStateStore>, audit_sink: Arc<dyn AuditSink>) -> Self {
        Self {
            trust_state,
            audit_sink,
            host_context_provider: Arc::new(StaticAsyncHostContextProvider::new(
                HostContext::default(),
            )),
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }

    pub fn with_host_context_provider(
        mut self,
        provider: Arc<dyn AsyncHostContextProvider>,
    ) -> Self {
        self.host_context_provider = provider;
        self
    }

    /// Sets the maximum JSON request body size accepted by the layer.
    ///
    /// Requests above this limit return `413 Payload Too Large`.
    /// Default: 1 MiB.
    pub fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }

    pub fn build(self) -> DelegatedLayer {
        DelegatedLayer {
            trust_state: self.trust_state,
            audit_sink: self.audit_sink,
            host_context_provider: self.host_context_provider,
            max_body_bytes: self.max_body_bytes,
        }
    }
}

/// A Tower [`Layer`] that validates delegated trust claims before passing
/// requests to the inner service.
///
/// The layer reads the raw JSON request body, runs it through the full trust
/// evaluation pipeline (normalize → signatures → lifetime → revocation → policy
/// → audit), and either passes the request to the inner service (on allow) or
/// returns a `403 Forbidden` JSON response (on deny). A `429` is returned when
/// the audit sink fails, `400` for malformed bodies, and `413` for request
/// bodies above the configured size limit.
///
/// The buffered body bytes are forwarded to the inner service unchanged so that
/// downstream axum handlers can still read them with `Json<T>`.
#[derive(Clone)]
pub struct DelegatedLayer {
    trust_state: Arc<dyn AsyncTrustStateStore>,
    audit_sink: Arc<dyn AuditSink>,
    host_context_provider: Arc<dyn AsyncHostContextProvider>,
    max_body_bytes: usize,
}

impl<S> Layer<S> for DelegatedLayer {
    type Service = DelegatedService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DelegatedService {
            inner,
            trust_state: Arc::clone(&self.trust_state),
            audit_sink: Arc::clone(&self.audit_sink),
            host_context_provider: Arc::clone(&self.host_context_provider),
            max_body_bytes: self.max_body_bytes,
        }
    }
}

/// The Tower [`Service`] produced by [`DelegatedLayer`].
#[derive(Clone)]
pub struct DelegatedService<S> {
    inner: S,
    trust_state: Arc<dyn AsyncTrustStateStore>,
    audit_sink: Arc<dyn AuditSink>,
    host_context_provider: Arc<dyn AsyncHostContextProvider>,
    max_body_bytes: usize,
}

impl<S> Service<Request<Body>> for DelegatedService<S>
where
    S: Service<Request<Body>, Response = Response, Error = std::convert::Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = std::convert::Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let trust_state = Arc::clone(&self.trust_state);
        let audit_sink = Arc::clone(&self.audit_sink);
        let host_context_provider = Arc::clone(&self.host_context_provider);
        let max_body_bytes = self.max_body_bytes;
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let (parts, body) = req.into_parts();

            if let Some(content_length) = parts
                .headers
                .get(CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<usize>().ok())
                && content_length > max_body_bytes
            {
                return Ok(json_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    json!({
                        "allowed": false,
                        "stage": "axum_layer",
                        "reason": format!("request body exceeds {} bytes", max_body_bytes)
                    }),
                ));
            }

            let bytes = match axum::body::to_bytes(body, max_body_bytes).await {
                Ok(b) => b,
                Err(e) => {
                    if e.to_string().contains("length limit exceeded") {
                        return Ok(json_response(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            json!({
                                "allowed": false,
                                "stage": "axum_layer",
                                "reason": format!("request body exceeds {} bytes", max_body_bytes)
                            }),
                        ));
                    }
                    return Ok(json_response(
                        StatusCode::BAD_REQUEST,
                        json!({"allowed":false,"stage":"axum_layer","reason":format!("failed to read body: {e}")}),
                    ));
                }
            };

            let raw_request: serde_json::Value = match serde_json::from_slice(&bytes) {
                Ok(v) => v,
                Err(e) => {
                    return Ok(json_response(
                        StatusCode::BAD_REQUEST,
                        json!({"allowed":false,"stage":"axum_layer","reason":format!("malformed JSON body: {e}")}),
                    ));
                }
            };

            let agent_id = raw_request
                .get("agent_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown-agent");
            let delegator_id = raw_request
                .get("delegator_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown-delegator");
            let host_context = host_context_provider.provide(agent_id, delegator_id);
            let now = Utc::now();

            match evaluate_and_audit_with_async_state(
                &raw_request,
                now,
                audit_sink.as_ref(),
                trust_state.as_ref(),
                &host_context,
            )
            .await
            {
                Ok(decision) if decision.allowed => {
                    let rebuilt = Request::from_parts(parts, Body::from(bytes));
                    inner.call(rebuilt).await
                }
                Ok(decision) => Ok(json_response(
                    StatusCode::FORBIDDEN,
                    json!({
                        "allowed": false,
                        "stage": decision.stage,
                        "reason": decision.reason
                    }),
                )),
                Err(e) => Ok(json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({"allowed":false,"stage":"audit_sink","reason":format!("failed to write audit event: {e}")}),
                )),
            }
        })
    }
}

fn json_response(status: StatusCode, body: serde_json::Value) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&body).expect("response serialization should succeed"),
        ))
        .expect("response builder should succeed")
}
