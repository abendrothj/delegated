use crate::models::{HostContext, PolicyCheck, RequestEnvelope, Violation};

const MIN_COGNITIVE_JUDGES: usize = 2;
const MIN_COGNITIVE_AVG_SCORE_BPS: u32 = 8_500;
const MIN_COGNITIVE_CHALLENGE_PASS_BPS: u16 = 9_000;
const REPUTATION_ALERT_THRESHOLD_BPS: u16 = 7_000;

pub fn evaluate_policy(
    envelope: RequestEnvelope,
    host_context: &HostContext,
) -> Result<RequestEnvelope, Violation> {
    let checks = simulate_policy(&envelope, host_context);
    if let Some(failure) = checks.iter().find(|check| !check.passed) {
        return Err(Violation::new("evaluate_policy", failure.reason.clone()));
    }
    Ok(envelope)
}

pub fn simulate_policy(envelope: &RequestEnvelope, host_context: &HostContext) -> Vec<PolicyCheck> {
    vec![
        check_allowed_action(envelope),
        check_cognitive_gate(host_context),
        check_reputation_risk_multiplier(host_context),
        check_calendar_constraint(envelope),
        check_email_domain_allowlist(envelope),
        check_max_spend(envelope),
        check_delegation_depth(envelope, host_context),
    ]
}

pub fn check_cognitive_gate(host_context: &HostContext) -> PolicyCheck {
    let Some(scores) = host_context.cognitive_judge_scores_bps.as_ref() else {
        // Cognitive verification is not configured; gate is skipped.
        return pass(
            "cognitive_gate",
            "cognitive verification not configured; gate skipped",
        );
    };
    if scores.len() < MIN_COGNITIVE_JUDGES {
        return fail(
            "cognitive_gate",
            "cognitive hard-deny requires at least two independent judge scores",
        );
    }

    let total: u32 = scores.iter().map(|score| *score as u32).sum();
    let average = total / scores.len() as u32;
    if average < MIN_COGNITIVE_AVG_SCORE_BPS {
        return fail(
            "cognitive_gate",
            "cognitive average score is below hard-deny threshold",
        );
    }

    let Some(challenge_pass_bps) = host_context.cognitive_challenge_pass_bps else {
        return fail(
            "cognitive_gate",
            "cognitive hard-deny requires cognitive_challenge_pass_bps",
        );
    };
    if challenge_pass_bps < MIN_COGNITIVE_CHALLENGE_PASS_BPS {
        return fail(
            "cognitive_gate",
            "cognitive challenge pass rate is below hard-deny threshold",
        );
    }

    pass(
        "cognitive_gate",
        "cognitive multi-judge and challenge-set thresholds satisfied",
    )
}

pub fn check_reputation_risk_multiplier(host_context: &HostContext) -> PolicyCheck {
    let Some(reputation_score) = host_context.reputation_score_bps else {
        return pass(
            "reputation_risk_multiplier",
            "no reputation score provided; no additional risk multiplier applied",
        );
    };

    if reputation_score >= REPUTATION_ALERT_THRESHOLD_BPS {
        return pass(
            "reputation_risk_multiplier",
            "reputation score is above risk multiplier threshold",
        );
    }

    if host_context.risk_challenge_passed.unwrap_or(false)
        || host_context.extra_approval_granted.unwrap_or(false)
    {
        return pass(
            "reputation_risk_multiplier",
            "low reputation accepted after additional challenge or approval",
        );
    }

    fail(
        "reputation_risk_multiplier",
        "low reputation requires additional challenge pass or explicit approval",
    )
}

pub fn check_allowed_action(envelope: &RequestEnvelope) -> PolicyCheck {
    let passed = envelope.token.allowed_actions.contains(&envelope.action);
    if passed {
        return PolicyCheck {
            name: "allowed_actions".to_string(),
            passed: true,
            reason: "action is allowed by delegation token".to_string(),
        };
    }

    PolicyCheck {
        name: "allowed_actions".to_string(),
        passed: false,
        reason: "requested action not in token allowed_actions".to_string(),
    }
}

pub fn check_calendar_constraint(envelope: &RequestEnvelope) -> PolicyCheck {
    let Some(constraints) = envelope.token.resource_constraints.as_ref() else {
        return pass("calendar_constraint", "no calendar constraint configured");
    };
    let Some(calendar_ids) = constraints.calendar_ids.as_ref() else {
        return pass("calendar_constraint", "no calendar constraint configured");
    };
    let Some(target_calendar) = envelope.runtime_context.target_calendar_id.as_ref() else {
        return pass(
            "calendar_constraint",
            "no target calendar provided for calendar constraint check",
        );
    };

    if calendar_ids.contains(target_calendar) {
        return pass(
            "calendar_constraint",
            "target calendar is allowed by resource constraints",
        );
    }

    fail(
        "calendar_constraint",
        "target calendar not allowed by token resource constraints",
    )
}

pub fn check_email_domain_allowlist(envelope: &RequestEnvelope) -> PolicyCheck {
    let Some(constraints) = envelope.token.resource_constraints.as_ref() else {
        return pass("email_domain_allowlist", "no email allowlist configured");
    };
    let Some(allowlist) = constraints.email_domain_allowlist.as_ref() else {
        return pass("email_domain_allowlist", "no email allowlist configured");
    };
    let Some(target_email) = envelope.runtime_context.target_email.as_ref() else {
        return pass(
            "email_domain_allowlist",
            "no target email provided for allowlist check",
        );
    };

    let Some((_, domain)) = target_email.rsplit_once('@') else {
        return fail(
            "email_domain_allowlist",
            "target email must contain a domain for allowlist check",
        );
    };

    if allowlist
        .iter()
        .any(|allowed_domain| allowed_domain == domain)
    {
        return pass(
            "email_domain_allowlist",
            "target email domain is allowed by resource constraints",
        );
    }

    fail(
        "email_domain_allowlist",
        "target email domain not allowed by token resource constraints",
    )
}

pub fn check_max_spend(envelope: &RequestEnvelope) -> PolicyCheck {
    let Some(max_spend) = envelope.token.max_spend.as_ref() else {
        return pass("max_spend", "no max spend configured");
    };
    let Some(requested_spend) = envelope.runtime_context.requested_spend else {
        return pass(
            "max_spend",
            "no requested spend provided for spend policy check",
        );
    };
    let Some(spend_currency) = envelope.runtime_context.spend_currency.as_ref() else {
        return fail(
            "max_spend",
            "requested spend requires runtime_context.spend_currency when token max_spend is configured",
        );
    };
    if spend_currency != &max_spend.currency {
        return fail(
            "max_spend",
            "requested spend currency does not match token max_spend currency",
        );
    }

    if requested_spend <= max_spend.amount {
        return pass("max_spend", "requested spend is within token max_spend");
    }

    fail("max_spend", "requested spend exceeds token max_spend")
}

pub fn check_delegation_depth(
    envelope: &RequestEnvelope,
    host_context: &HostContext,
) -> PolicyCheck {
    let Some(max_depth) = envelope.token.max_delegation_depth else {
        return pass("delegation_depth", "no max delegation depth configured");
    };
    let Some(request_depth) = host_context.delegation_depth else {
        return pass(
            "delegation_depth",
            "no runtime delegation depth provided for depth check",
        );
    };

    if request_depth <= max_depth {
        return pass(
            "delegation_depth",
            "delegation depth is within token max_delegation_depth",
        );
    }

    fail(
        "delegation_depth",
        "delegation depth exceeds token max_delegation_depth",
    )
}

/// Evaluates the `extra` map in `resource_constraints` using a caller-supplied closure.
///
/// # Not called by `DefaultPolicy` — opt-in enforcement required
///
/// [`DefaultPolicy`] does **not** invoke this function. Any extra constraints encoded in a
/// token's `resource_constraints.extra` map are **silently ignored** unless your deployment
/// provides a custom [`Policy`] implementation that explicitly calls `check_extra_constraints`.
///
/// To enforce extra constraints, call this inside your custom policy's `evaluate` method:
///
/// ```rust,ignore
/// use delegated::{DefaultPolicy, Policy, check_extra_constraints};
/// use delegated::models::{HostContext, PolicyCheck, RequestEnvelope};
///
/// struct MyPolicy;
/// impl Policy for MyPolicy {
///     fn evaluate(&self, envelope: &RequestEnvelope, ctx: &HostContext) -> Vec<PolicyCheck> {
///         let mut checks = DefaultPolicy.evaluate(envelope, ctx);
///         checks.extend(check_extra_constraints(envelope, &|key, values, env| {
///             // enforce your domain-specific constraints here
///             PolicyCheck {
///                 name: key.to_string(),
///                 passed: values.contains(&env.action.clone()),
///                 reason: format!("{key} constraint evaluated"),
///             }
///         }));
///         checks
///     }
/// }
/// ```
///
/// Returns one [`PolicyCheck`] per entry in `extra`. Returns an empty `Vec` when there are
/// no `resource_constraints` or the `extra` map is empty.
pub fn check_extra_constraints(
    envelope: &RequestEnvelope,
    evaluator: &dyn Fn(&str, &[String], &RequestEnvelope) -> PolicyCheck,
) -> Vec<PolicyCheck> {
    let Some(constraints) = envelope.token.resource_constraints.as_ref() else {
        return Vec::new();
    };
    constraints
        .extra
        .iter()
        .map(|(key, values)| evaluator(key, values, envelope))
        .collect()
}

fn pass(name: &str, reason: &str) -> PolicyCheck {
    PolicyCheck {
        name: name.to_string(),
        passed: true,
        reason: reason.to_string(),
    }
}

fn fail(name: &str, reason: &str) -> PolicyCheck {
    PolicyCheck {
        name: name.to_string(),
        passed: false,
        reason: reason.to_string(),
    }
}
