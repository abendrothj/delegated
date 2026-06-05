# Operations Runbook

This runbook targets small teams running `delegated` in production.

See also: [`KNOWN_LIMITS.md`](KNOWN_LIMITS.md)

## Deployment profile

1. Use shared trust state (`RedisTrustStateStore`) for multi-instance services.
2. Keep middleware request size limits explicit (`with_max_body_bytes`).
3. Use short-lived delegation tokens and rotate identity keys regularly.

## Minimal production checks

Run before deploy:

```bash
./scripts/release_check.sh
```

Dependency review quick pass:

```bash
cargo tree
cargo tree -i serde_json
```

Release provenance check is included in `release_check.sh` (`scripts/verify_release_provenance.sh`).
For tag-cut/release candidates, run with strict enforcement:

```bash
DELEGATED_REQUIRE_VERSION_TAG_ON_HEAD=1 ./scripts/verify_release_provenance.sh
```

Run conformance regression:

```bash
./scripts/conformance.sh
```

Run external interop checks against third-party adapter deployments:

```bash
DELEGATED_INTEROP_HTTP_URL=https://interop.example.com/trust \
DELEGATED_INTEROP_MCP_URL=https://interop.example.com/mcp \
DELEGATED_INTEROP_A2A_URL=https://interop.example.com/a2a \
./scripts/external_interop.sh
```

## Runtime health signals

Monitor:

- deny-rate by stage (`normalize_request`, `verify_signatures`, `evaluate_policy`)
- revocation backend availability/errors
- audit sink write failures
- p95/p99 trust evaluation latency

## Incident response shortcuts

### Compromised token

1. Revoke via control plane or CLI.
2. Verify deny behavior with a replay request.
3. Export audit events and preserve timeline.

### Compromised agent identity

1. Add agent to emergency deny list.
2. Rotate associated keys and reissue identity document.
3. Remove emergency deny only after validation.

### Revocation backend outage

`delegated` is fail-closed. During outage, requests are denied by design.

1. Restore backend first.
2. Confirm state queries succeed.
3. Replay validation requests to verify recovery.
