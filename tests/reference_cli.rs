use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{TimeZone, Utc};
use delegated::models::{
    AgentEndpoint, AgentIdentityDocument, DelegationToken, MaxSpend, PublicKeyRecord,
    RequestEnvelope, RuntimeContext, TrustProfile,
};
use delegated::{
    DelegationGrantProposal, FileBackedTrustState, TOKEN_SIGNATURE_ALG_ED25519, TrustStateStore,
    sign_delegation_token, sign_identity_document,
};
use ed25519_dalek::SigningKey;
use serde_json::Value;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[23u8; 32])
}

fn private_key_base64url() -> String {
    Base64UrlUnpadded::encode_string(&signing_key().to_bytes())
}

fn unique_id() -> String {
    let counter = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time should be after epoch")
        .as_nanos();
    format!("{counter}_{nanos}")
}

fn sample_token() -> DelegationToken {
    let unique_id = unique_id();
    DelegationToken {
        spec_version: "0.1".to_string(),
        kind: "DelegationToken".to_string(),
        token_id: format!("dlg_cli_{unique_id}"),
        issuer: "https://trust.example.ai".to_string(),
        agent_id: "agent:example:scheduler:v1".to_string(),
        delegator_id: "user:jake-abendroth".to_string(),
        owner_id: "org:example".to_string(),
        audience: vec!["tool:google-calendar".to_string()],
        allowed_actions: vec!["calendar.create_event".to_string()],
        resource_constraints: None,
        max_spend: None,
        max_delegation_depth: Some(0),
        approval_policy: None,
        issued_at: Utc
            .with_ymd_and_hms(2024, 6, 1, 20, 10, 0)
            .single()
            .expect("valid timestamp"),
        expires_at: Utc
            .with_ymd_and_hms(2099, 6, 1, 20, 40, 0)
            .single()
            .expect("valid timestamp"),
        intent: None,
        nonce: format!("nonce-cli-{unique_id}"),
        key_id: "key-2026-01".to_string(),
        signature_alg: TOKEN_SIGNATURE_ALG_ED25519.to_string(),
        signature: String::new(),
    }
}

fn signed_request_json() -> Value {
    let unique_id = unique_id();
    let key = signing_key();
    let mut identity_document = AgentIdentityDocument {
        spec_version: "0.1".to_string(),
        kind: "AgentIdentityDocument".to_string(),
        agent_id: "agent:example:scheduler:v1".to_string(),
        display_name: Some("example Scheduler Agent".to_string()),
        owner_id: "org:example".to_string(),
        issuer: "https://trust.example.ai".to_string(),
        identity_type: "spiffe".to_string(),
        subject: "spiffe://example.ai/agents/scheduler".to_string(),
        public_keys: vec![PublicKeyRecord {
            kid: "key-2026-01".to_string(),
            kty: "OKP".to_string(),
            crv: Some(TOKEN_SIGNATURE_ALG_ED25519.to_string()),
            x: Some(Base64UrlUnpadded::encode_string(
                &key.verifying_key().to_bytes(),
            )),
        }],
        supported_protocols: vec!["http".to_string()],
        supported_auth_methods: vec!["delegation_token".to_string()],
        capabilities: None,
        endpoints: vec![AgentEndpoint {
            protocol: "http".to_string(),
            url: "https://agents.example.ai/scheduler".to_string(),
        }],
        attestation: None,
        created_at: Utc
            .with_ymd_and_hms(2026, 6, 1, 20, 0, 0)
            .single()
            .expect("valid timestamp"),
        expires_at: Utc
            .with_ymd_and_hms(2026, 6, 8, 20, 0, 0)
            .single()
            .expect("valid timestamp"),
        signature: String::new(),
    };
    identity_document.signature =
        sign_identity_document(&identity_document, &key).expect("identity signing should work");

    let mut token = sample_token();
    token.signature = sign_delegation_token(&token, &key).expect("token signing should work");

    let request = RequestEnvelope {
        spec_version: "0.1".to_string(),
        kind: "TrustRequestEnvelope".to_string(),
        request_id: Some(format!("req_cli_verify_{unique_id}")),
        profile: TrustProfile::Developer,
        agent_id: "agent:example:scheduler:v1".to_string(),
        delegator_id: "user:jake-abendroth".to_string(),
        audience: "tool:google-calendar".to_string(),
        action: "calendar.create_event".to_string(),
        resource: None,
        runtime_context: RuntimeContext {
            requested_spend: None,
            spend_currency: None,
            delegation_depth: Some(0),
            target_email: None,
            target_calendar_id: None,
            cognitive_judge_scores_bps: Some(vec![9300, 9100]),
            cognitive_challenge_pass_bps: Some(9200),
            reputation_score_bps: Some(8300),
            risk_challenge_passed: None,
            extra_approval_granted: None,
        },
        identity_document: Some(identity_document),
        token,
    };

    serde_json::to_value(request).expect("request serialization should work")
}

fn sample_proposal() -> DelegationGrantProposal {
    DelegationGrantProposal {
        request_id: format!("req_cli_grant_{}", unique_id()),
        delegator_id: "user:jake-abendroth".to_string(),
        agent_id: "agent:example:scheduler:v1".to_string(),
        owner_id: "org:example".to_string(),
        intent: "schedule_demo".to_string(),
        audience: vec!["tool:google-calendar".to_string()],
        allowed_actions: vec!["calendar.create_event".to_string()],
        max_spend: Some(MaxSpend {
            amount: 0,
            currency: "USD".to_string(),
        }),
        expires_at: Utc
            .with_ymd_and_hms(2099, 6, 1, 20, 40, 0)
            .single()
            .expect("valid timestamp"),
    }
}

#[test]
fn cli_signs_token_with_ed25519() {
    let temp_dir = std::env::temp_dir().join(format!(
        "delegated_cli_sign_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).expect("temp directory should be creatable");
    let token_path = temp_dir.join("token.json");
    std::fs::write(
        &token_path,
        serde_json::to_string_pretty(&sample_token()).expect("token serialization should work"),
    )
    .expect("token file should be writable");

    let output = Command::new(env!("CARGO_BIN_EXE_delegated-cli"))
        .arg("sign-token")
        .arg(token_path.to_string_lossy().to_string())
        .arg(private_key_base64url())
        .output()
        .expect("CLI should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let signed: DelegationToken = serde_json::from_str(&stdout).expect("signed token should parse");
    assert_eq!(signed.signature_alg, TOKEN_SIGNATURE_ALG_ED25519);
    assert!(!signed.signature.is_empty());

    std::fs::remove_dir_all(temp_dir).expect("temp directory should be removable");
}

#[test]
fn cli_verifies_request_and_returns_success_exit_code() {
    let temp_dir = std::env::temp_dir().join(format!(
        "delegated_cli_verify_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).expect("temp directory should be creatable");
    let request_path = temp_dir.join("request.json");
    std::fs::write(
        &request_path,
        serde_json::to_string_pretty(&signed_request_json())
            .expect("request serialization should work"),
    )
    .expect("request file should be writable");

    let output = Command::new(env!("CARGO_BIN_EXE_delegated-cli"))
        .arg("verify-request")
        .arg(request_path.to_string_lossy().to_string())
        .output()
        .expect("CLI should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert!(stdout.contains("\"allowed\": true"));

    std::fs::remove_dir_all(temp_dir).expect("temp directory should be removable");
}

#[test]
fn cli_approves_grant_and_emits_callback_payload() {
    let temp_dir = std::env::temp_dir().join(format!(
        "delegated_cli_approve_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).expect("temp directory should be creatable");
    let proposal_path = temp_dir.join("proposal.json");
    let proposal = sample_proposal();
    std::fs::write(
        &proposal_path,
        serde_json::to_string_pretty(&proposal).expect("proposal serialization should work"),
    )
    .expect("proposal file should be writable");

    let output = Command::new(env!("CARGO_BIN_EXE_delegated-cli"))
        .arg("approve-grant")
        .arg(proposal_path.to_string_lossy().to_string())
        .arg("approve")
        .arg("user:jake-abendroth")
        .arg("--reason")
        .arg("approved")
        .arg("--token-id")
        .arg("dlg_cli_grant")
        .output()
        .expect("CLI should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let payload: Value = serde_json::from_str(&stdout).expect("approve payload should parse");
    assert_eq!(
        payload["operation"]["receipt"]["status"],
        serde_json::json!("Approved")
    );
    assert_eq!(
        payload["operation"]["callback"]["request_id"],
        serde_json::json!(proposal.request_id)
    );

    std::fs::remove_dir_all(temp_dir).expect("temp directory should be removable");
}

#[test]
fn cli_revokes_token_and_persists_state_update() {
    let temp_dir = std::env::temp_dir().join(format!(
        "delegated_cli_revoke_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).expect("temp directory should be creatable");
    let state_path = temp_dir.join("trust-state.json");
    let token_id = format!("dlg_cli_revoke_{}", unique_id());
    let output = Command::new(env!("CARGO_BIN_EXE_delegated-cli"))
        .env(
            "DELEGATED_TRUST_STATE_PATH",
            state_path.to_string_lossy().to_string(),
        )
        .arg("revoke-token")
        .arg("req_cli_revoke")
        .arg(&token_id)
        .arg("user:jake-abendroth")
        .arg("--reason")
        .arg("manual revoke")
        .output()
        .expect("CLI should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let payload: Value = serde_json::from_str(&stdout).expect("revoke payload should parse");
    assert_eq!(payload["receipt"]["status"], serde_json::json!("Revoked"));
    let state = FileBackedTrustState::new(state_path);
    assert!(
        state
            .is_token_revoked(&token_id)
            .expect("state query should succeed")
    );

    std::fs::remove_dir_all(temp_dir).expect("temp directory should be removable");
}
