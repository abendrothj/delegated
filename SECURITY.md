# Security Policy

`signet` is a fail-closed trust layer. Security issues are treated as highest priority.

## Reporting a vulnerability

Please report vulnerabilities privately by opening a GitHub security advisory for this repository.

- Include affected version(s), impact, and a minimal reproduction.
- If possible, include a proposed fix or mitigation.
- Do not open public issues for exploitable vulnerabilities.

## Scope and threat model

`signet` defends request-time delegation trust boundaries:

- signature verification for identity documents and delegation tokens
- replay protection via nonce consumption
- revocation and emergency deny checks
- strict allow/deny policy evaluation with audit logging

`signet` does **not** replace infrastructure hardening. Deployments still need:

- secure key management and rotation
- secure transport (TLS/mTLS as appropriate)
- host-side trust signal integrity for `HostContext`
- operational monitoring and incident response

## Hardening guidance

1. Use shared state (`RedisTrustStateStore`) for distributed deployments.
2. Keep identity/token lifetimes short and rotate signing keys.
3. Enforce body-size limits in middleware (`TrustLayerBuilder::with_max_body_bytes`).
4. Treat `runtime_context` as untrusted request input; source trust signals from `HostContext`.

