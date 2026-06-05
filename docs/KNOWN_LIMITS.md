# Known Limits

This document captures intentional limits and current constraints in `delegated`.
It is a production-facing artifact: read this before deploying at scale.

## Scope and protocol limits

1. **Spec version support is explicit and finite**
   - Only versions in `SUPPORTED_SPEC_VERSIONS` are accepted.
   - Current support: `0.1`.

2. **Identity document requirement in offline path**
   - Offline signature verification requires `identity_document`.
   - In OIDC bridge mode, token signature still depends on identity-document key material.

3. **Policy semantics are deterministic but host-signal dependent**
   - Several checks depend on trusted `HostContext` fields.
   - If host signals are missing, behavior follows documented pass/fail defaults in policy checks.

## Security and trust limits

1. **`runtime_context` is untrusted input**
   - Must not be treated as authoritative for delegation depth/risk/reputation/approval signals.
   - Those belong in `HostContext`.

2. **No built-in key management system**
   - Key custody, rotation orchestration, HSM/KMS integration, and key revocation lifecycle are external responsibilities.

3. **No built-in transport security**
   - TLS/mTLS termination and network controls are deployment responsibilities.

4. **No built-in compliance controls**
   - SOC2/ISO/GDPR controls, retention governance, and legal policy enforcement are out of scope.

## Operational limits

1. **File-backed trust state is not for distributed production**
   - `FileBackedTrustState` is suitable for CLI/single-process usage.
   - Multi-instance production should use shared state (e.g., Redis-backed async store).

2. **Audit sink durability depends on sink implementation**
   - `JsonlFileAuditSink` writes to local filesystem; it does not provide centralized durability by itself.
   - Production deployments should forward/persist audit data to durable infrastructure.

3. **Middleware body limits are opt-configurable**
   - Axum middleware defaults to 1 MiB.
   - You are responsible for setting limits appropriate to your traffic profile.

4. **Fail-closed behavior can increase deny-rate during dependency incidents**
   - Revocation backend outages intentionally deny requests.
   - This protects security but may impact availability until dependencies recover.

5. **Adapter guard is process-local**
   - Guard counters are maintained in process-local sharded maps and reset on process restart.
   - Multi-instance global throttling still requires infrastructure-level controls (gateway/shared counters).

6. **Convenience runtime state is process-local**
   - Default convenience APIs use process-shared in-memory trust state (replay persistence across calls in one process).
   - Cross-instance persistence still requires a shared backend (for example Redis or a durable file path for single-instance deployments).

7. **Production shared-backend enforcement is opt-in**
   - Set `DELEGATED_REQUIRE_SHARED_BACKEND=1` (or `DELEGATED_ENV=production`) to fail closed on non-shared runtime paths.
   - Without this flag, convenience APIs remain available for local/dev usage.

## Performance limits

1. **Throughput is environment-dependent**
   - Baselines from `examples/eval_benchmark.rs` are local indicators, not SLA guarantees.

2. **Redis behavior depends on deployment topology**
   - Latency and consistency characteristics depend on Redis network/location/configuration.

3. **No internal queueing/backpressure subsystem**
   - Rate/concurrency protection is adapter-level (`guard`) and infrastructure-level controls are still required.

4. **Benchmark example is not a production SLA measurement**
   - `examples/eval_benchmark.rs` is useful for local baseline comparisons.
   - It should not be treated as a representative multi-instance p95/p99 production benchmark.

5. **`JsonlFileAuditSink` `NewestFirst` reads are O(limit) for the limit-only case, but O(file size) when a `since` filter is active**
   - When `AuditOrder::NewestFirst` is used without a `since` filter, the reader seeks backward through the file in 64 KiB chunks and stops as soon as `limit` events are collected.
   - When a `since` timestamp is provided, the reader must continue scanning backward until it finds events older than `since` (because JSONL files are not guaranteed to be strictly chronological). In the worst case (very old `since` or a large gap), this still scans the whole file.
   - For production audit workloads at scale, forward the JSONL stream to a purpose-built log store (e.g., OpenSearch, ClickHouse, Loki) that indexes timestamps and can execute time-range queries efficiently.

## Ecosystem and maturity limits

1. **Early-stage project surface**
   - APIs are stabilizing toward v1, but downstream consumers should expect continued hardening iterations.

2. **Limited first-party integrations**
   - Core protocol adapters are included; broader ecosystem integrations remain incremental.

## Upgrade and compatibility limits

1. **Breaking-change policy is pre-v1**
   - Until v1 contract freeze, minor release updates can refine behavior or API details.

2. **Schema and model alignment follows code authority**
   - Rust model/runtime behavior is authoritative.
   - Schema/docs are maintained to match implementation, but should be verified during upgrades.
