use crate::models::{HostContext, PolicyCheck, RequestEnvelope};

/// Extension point for custom authorization logic. Implement this trait to replace
/// or augment the built-in checks. Pass a `&dyn Policy` to the `*_with_policy`
/// engine variants.
///
/// The trait is object-safe — no generics, no `Self` in return position.
pub trait Policy: Send + Sync {
    fn evaluate(&self, envelope: &RequestEnvelope, host_context: &HostContext) -> Vec<PolicyCheck>;
}

/// The built-in policy that runs all standard checks bundled with `signet`.
///
/// **Does not evaluate `resource_constraints.extra`.**
/// If your tokens carry custom extra constraints, you must supply a custom [`Policy`]
/// that calls [`check_extra_constraints`] — see its documentation for an example.
///
/// Compose with your own checks by calling `DefaultPolicy.evaluate(...)` and appending:
///
/// ```rust,ignore
/// use signet::{DefaultPolicy, Policy};
/// use signet::models::{HostContext, PolicyCheck, RequestEnvelope};
///
/// struct MyPolicy;
///
/// impl Policy for MyPolicy {
///     fn evaluate(&self, envelope: &RequestEnvelope, host_context: &HostContext) -> Vec<PolicyCheck> {
///         let mut checks = DefaultPolicy.evaluate(envelope, host_context);
///         // add domain-specific checks here
///         checks
///     }
/// }
/// ```
pub struct DefaultPolicy;

impl Policy for DefaultPolicy {
    fn evaluate(&self, envelope: &RequestEnvelope, host_context: &HostContext) -> Vec<PolicyCheck> {
        crate::policy::simulate_policy(envelope, host_context)
    }
}
