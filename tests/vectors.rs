// Reference vector tests — loaded from tests/fixtures/vectors.json
// Generate with: cargo run --example gen_vectors > tests/fixtures/vectors.json

use chrono::DateTime;
use serde_json::Value;
use signet::{InMemoryTrustState, evaluate_request_with_state};
use signet::models::HostContext;

const VECTORS_JSON: &str = include_str!("fixtures/vectors.json");

#[test]
fn reference_vectors() {
    let manifest: Value =
        serde_json::from_str(VECTORS_JSON).expect("vectors.json must be valid JSON");

    let vectors = manifest["vectors"]
        .as_array()
        .expect("manifest must have a `vectors` array");

    let mut failures: Vec<String> = Vec::new();

    for v in vectors {
        let id = v["id"].as_str().unwrap_or("<unknown>");
        let description = v["description"].as_str().unwrap_or("");
        let evaluate_at_str = v["evaluate_at"].as_str().expect("evaluate_at must be a string");
        let envelope = &v["envelope"];
        let expected_allowed = v["expected"]["allowed"]
            .as_bool()
            .expect("expected.allowed must be bool");
        let expected_stage = v["expected"]["stage"]
            .as_str()
            .expect("expected.stage must be a string");
        let expected_reason = v["expected"]["reason"]
            .as_str()
            .expect("expected.reason must be a string");

        let evaluate_at = DateTime::parse_from_rfc3339(evaluate_at_str)
            .unwrap_or_else(|_| panic!("vector {id}: invalid evaluate_at timestamp"))
            .into();

        let trust_state = InMemoryTrustState::new();
        let host_ctx = HostContext::default();

        let (decision, _audit) =
            evaluate_request_with_state(envelope, evaluate_at, &trust_state, &host_ctx);

        let mut errs: Vec<String> = Vec::new();

        if decision.allowed != expected_allowed {
            errs.push(format!(
                "  allowed: got {}, want {}",
                decision.allowed, expected_allowed
            ));
        }
        if decision.stage != expected_stage {
            errs.push(format!(
                "  stage: got {:?}, want {:?}",
                decision.stage, expected_stage
            ));
        }
        if !decision.reason.contains(expected_reason) {
            errs.push(format!(
                "  reason: got {:?}, want substring {:?}",
                decision.reason, expected_reason
            ));
        }

        if !errs.is_empty() {
            failures.push(format!(
                "FAIL [{id}] {description}\n{}",
                errs.join("\n")
            ));
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} vector(s) failed:\n\n{}",
            failures.len(),
            failures.join("\n\n")
        );
    }

    println!("All {} reference vectors passed.", vectors.len());
}
