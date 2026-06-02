use crate::models::{PolicyCheck, RequestEnvelope, Violation};

const MIN_COGNITIVE_JUDGES: usize = 2;
const MIN_COGNITIVE_AVG_SCORE_BPS: u32 = 8_500;
const MIN_COGNITIVE_CHALLENGE_PASS_BPS: u16 = 9_000;
const REPUTATION_ALERT_THRESHOLD_BPS: u16 = 7_000;

pub fn evaluate_policy(envelope: RequestEnvelope) -> Result<RequestEnvelope, Violation> {
    let checks = simulate_policy(&envelope);
    if let Some(failure) = checks.iter().find(|check| !check.passed) {
        return Err(Violation::new("evaluate_policy", failure.reason.clone()));
    }
    Ok(envelope)
}

pub fn simulate_policy(envelope: &RequestEnvelope) -> Vec<PolicyCheck> {
    let mut checks = Vec::new();

    checks.push(check_allowed_action(envelope));
    checks.push(check_cognitive_gate(envelope));
    checks.push(check_reputation_risk_multiplier(envelope));
    checks.push(check_calendar_constraint(envelope));
    checks.push(check_email_domain_allowlist(envelope));
    checks.push(check_max_spend(envelope));
    checks.push(check_delegation_depth(envelope));

    checks
}

fn check_cognitive_gate(envelope: &RequestEnvelope) -> PolicyCheck {
    let Some(scores) = envelope.runtime_context.cognitive_judge_scores_bps.as_ref() else {
        return fail(
            "cognitive_gate",
            "cognitive hard-deny requires runtime cognitive_judge_scores_bps",
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

    let Some(challenge_pass_bps) = envelope.runtime_context.cognitive_challenge_pass_bps else {
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

fn check_reputation_risk_multiplier(envelope: &RequestEnvelope) -> PolicyCheck {
    let Some(reputation_score) = envelope.runtime_context.reputation_score_bps else {
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

    if envelope
        .runtime_context
        .risk_challenge_passed
        .unwrap_or(false)
        || envelope
            .runtime_context
            .extra_approval_granted
            .unwrap_or(false)
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

fn check_allowed_action(envelope: &RequestEnvelope) -> PolicyCheck {
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

fn check_calendar_constraint(envelope: &RequestEnvelope) -> PolicyCheck {
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

fn check_email_domain_allowlist(envelope: &RequestEnvelope) -> PolicyCheck {
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

fn check_max_spend(envelope: &RequestEnvelope) -> PolicyCheck {
    let Some(max_spend) = envelope.token.max_spend.as_ref() else {
        return pass("max_spend", "no max spend configured");
    };
    let Some(requested_spend) = envelope.runtime_context.requested_spend else {
        return pass(
            "max_spend",
            "no requested spend provided for spend policy check",
        );
    };

    if requested_spend <= max_spend.amount {
        return pass("max_spend", "requested spend is within token max_spend");
    }

    fail("max_spend", "requested spend exceeds token max_spend")
}

fn check_delegation_depth(envelope: &RequestEnvelope) -> PolicyCheck {
    let Some(max_depth) = envelope.token.max_delegation_depth else {
        return pass("delegation_depth", "no max delegation depth configured");
    };
    let Some(request_depth) = envelope.runtime_context.delegation_depth else {
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
