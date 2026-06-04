# Security Checklist (production)

Use this checklist before every production rollout.

## A. Build and test gates

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo test`
- [ ] `./scripts/conformance.sh`
- [ ] `./scripts/release_check.sh`

## B. Configuration and deployment

- [ ] Axum middleware configured with explicit body limit via `with_max_body_bytes`.
- [ ] Multi-instance deployment uses shared revocation state (`RedisTrustStateStore`).
- [ ] Token and identity lifetimes are short enough for incident response.
- [ ] Emergency deny and token revocation operational path is tested.

## C. Key and identity hygiene

- [ ] Signing keys are managed outside source control.
- [ ] Key rotation path tested (identity document supports additional keys).
- [ ] `key_id` handling validated across issuance and verification path.

## D. Runtime trust-signal discipline

- [ ] `HostContext` is sourced only from trusted infrastructure.
- [ ] Request `runtime_context` is treated as untrusted caller input.
- [ ] Delegation depth, cognitive/reputation/risk, and approval signals are not taken from request JSON.

## E. Monitoring and incident readiness

- [ ] Deny-stage metrics/alerts are active (`normalize_request`, `verify_signatures`, `evaluate_policy`, revocation stage).
- [ ] Audit sink writes are monitored for errors.
- [ ] Runbook for token compromise and emergency deny is documented and tested.

## Code-path map

- Input normalization/contract checks: `src/stages.rs::normalize_request`, `src/contracts.rs`
- Signature checks: `src/stages.rs::verify_signatures`, `src/crypto.rs`
- Lifetime/binding checks: `src/stages.rs::{validate_identity_document_lifetime, validate_token_lifetime, validate_token_binding}`
- Replay/revocation/deny: `src/stages.rs::enforce_revocation_and_redelegation`, `src/stages_async.rs::enforce_revocation_and_redelegation_async`, `src/revocation*.rs`
- Policy checks: `src/policy.rs`
- Audit pipeline: `src/engine.rs`, `src/audit.rs`
- Axum size limit handling: `src/adapters/axum_layer.rs`

