use crate::models::{PolicyCheck, RequestEnvelope, Violation};

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
    checks.push(check_calendar_constraint(envelope));
    checks.push(check_email_domain_allowlist(envelope));
    checks.push(check_max_spend(envelope));
    checks.push(check_delegation_depth(envelope));

    checks
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
