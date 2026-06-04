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

## Performance limits

1. **Throughput is environment-dependent**
   - Baselines from `examples/eval_benchmark.rs` are local indicators, not SLA guarantees.

2. **Redis behavior depends on deployment topology**
   - Latency and consistency characteristics depend on Redis network/location/configuration.

3. **No internal queueing/backpressure subsystem**
   - Rate/concurrency protection is adapter-level (`guard`) and infrastructure-level controls are still required.

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

