# Integration Guide (30-minute path)

## 1. Add dependency

```toml
[dependencies]
delegated = { version = "0.1.1", features = ["axum"] }
```

Use `redis` + `async` features for distributed trust state.

## 2. Install middleware

```rust
use std::sync::Arc;
use delegated::{DelegatedLayerBuilder, InMemoryAsyncTrustState, JsonlFileAuditSink};

let trust_state = Arc::new(InMemoryAsyncTrustState::new());
let audit_sink = Arc::new(JsonlFileAuditSink::new("audit.jsonl"));
let layer = DelegatedLayerBuilder::new(trust_state, audit_sink)
    .with_max_body_bytes(1024 * 1024)
    .build();
```

`InMemoryAsyncTrustState` is for local/dev validation. Use a shared backend (for example `RedisTrustStateStore`) before multi-instance production deployment.
For hard enforcement, set `DELEGATED_REQUIRE_SHARED_BACKEND=1` (or `DELEGATED_ENV=production`) in production.

Attach this layer before protected handlers.

## 3. Validate with signed sample request

Generate a valid request:

```bash
cargo run --example build_request
```

Send to your protected route as JSON.

## 4. Add operational safeguards

1. Configure a durable audit sink.
2. Move from in-memory trust state to Redis before multi-node deployment.
3. Keep body-size limits explicit.
4. Add deny-stage metrics to monitoring.

## 5. Verify conformance

```bash
./scripts/conformance.sh
```

For third-party adapter deployments, run `./scripts/external_interop.sh` with endpoint env vars to validate real interoperability.
