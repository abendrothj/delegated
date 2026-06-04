use crate::models::{HostContext, RequestEnvelope, Violation};
use crate::revocation_async::AsyncTrustStateStore;

pub async fn enforce_revocation_and_redelegation_async(
    envelope: RequestEnvelope,
    state: &dyn AsyncTrustStateStore,
    host_context: &HostContext,
) -> Result<RequestEnvelope, Violation> {
    let is_revoked = state
        .is_token_revoked(&envelope.token.token_id)
        .await
        .map_err(|reason| {
            Violation::new(
                "enforce_revocation_and_redelegation",
                format!("{reason} (fail-closed)"),
            )
        })?;
    if is_revoked {
        return Err(Violation::new(
            "enforce_revocation_and_redelegation",
            "delegation token has been revoked",
        ));
    }

    let is_agent_denied = state
        .is_agent_emergency_denied(&envelope.agent_id)
        .await
        .map_err(|reason| {
            Violation::new(
                "enforce_revocation_and_redelegation",
                format!("{reason} (fail-closed)"),
            )
        })?;
    if is_agent_denied {
        return Err(Violation::new(
            "enforce_revocation_and_redelegation",
            "agent is blocked by emergency deny list",
        ));
    }

    let nonce_was_new = state
        .consume_nonce(&envelope.token.nonce, envelope.token.expires_at)
        .await
        .map_err(|reason| {
            Violation::new(
                "enforce_revocation_and_redelegation",
                format!("{reason} (fail-closed)"),
            )
        })?;
    if !nonce_was_new {
        return Err(Violation::new(
            "enforce_revocation_and_redelegation",
            "delegation token nonce replay detected",
        ));
    }

    if let Some(max_depth) = envelope.token.max_delegation_depth {
        let runtime_depth = host_context.delegation_depth.unwrap_or(0);
        if runtime_depth > max_depth {
            return Err(Violation::new(
                "enforce_revocation_and_redelegation",
                "runtime delegation depth exceeds token max_delegation_depth",
            ));
        }
    }

    Ok(envelope)
}
