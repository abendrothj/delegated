use crate::models::{AgentIdentityDocument, Violation};

/// Pluggable identity verifier for the OIDC bridge feature.
///
/// Implementations can validate `AgentIdentityDocument` against an external OIDC
/// provider instead of (or in addition to) the built-in offline Ed25519 verification.
/// Implement this trait against your OIDC provider's JWKS endpoint or any other
/// external trust source.
pub trait IdentityVerifier: Send + Sync {
    fn verify(&self, identity_document: &AgentIdentityDocument) -> Result<(), Violation>;
}

/// A sentinel verifier that always denies. Use this when you want the OIDC bridge
/// feature enabled but require every request to supply an explicit verifier — any
/// call that falls through without one will be rejected at the `verify_signatures`
/// stage rather than silently falling back to offline verification.
pub struct RequireExplicitVerifier;

impl IdentityVerifier for RequireExplicitVerifier {
    fn verify(&self, _: &AgentIdentityDocument) -> Result<(), Violation> {
        Err(Violation::new(
            "verify_signatures",
            "identity document requires explicit OIDC verification but none was provided",
        ))
    }
}
