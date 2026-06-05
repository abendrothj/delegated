use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::Utc;
use delegated::models::{AgentIdentityDocument, DelegationToken};
use delegated::{
    ApprovalDecision, DelegationGrantProposal, FileBackedTrustState, TOKEN_SIGNATURE_ALG_ED25519,
    default_trust_state_path, evaluate_request_with_state, record_approval_decision,
    render_cli_grant_summary, revoke_token_with_receipt, sign_delegation_token,
    sign_identity_document,
};
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<ExitCode, Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "help".to_string());

    match command.as_str() {
        "sign-identity" => {
            let input = required_arg(args.next(), "input json path")?;
            let private_key = required_arg(args.next(), "private key (base64url-no-pad)")?;
            let output = args.next();
            sign_identity_command(&input, &private_key, output.as_deref())?;
            Ok(ExitCode::SUCCESS)
        }
        "sign-token" => {
            let input = required_arg(args.next(), "input json path")?;
            let private_key = required_arg(args.next(), "private key (base64url-no-pad)")?;
            let output = args.next();
            sign_token_command(&input, &private_key, output.as_deref())?;
            Ok(ExitCode::SUCCESS)
        }
        "verify-request" => {
            let input = required_arg(args.next(), "input json path")?;
            verify_request_command(&input)
        }
        "approve-grant" => {
            let proposal = required_arg(args.next(), "proposal json path")?;
            let decision = required_arg(args.next(), "decision (approve|deny)")?;
            let actor_id = required_arg(args.next(), "actor id")?;
            let mut reason: Option<String> = None;
            let mut token_id: Option<String> = None;
            let mut output: Option<String> = None;
            while let Some(flag) = args.next() {
                match flag.as_str() {
                    "--reason" => {
                        reason = Some(required_arg(args.next(), "--reason value")?);
                    }
                    "--token-id" => {
                        token_id = Some(required_arg(args.next(), "--token-id value")?);
                    }
                    "--output" => {
                        output = Some(required_arg(args.next(), "--output value")?);
                    }
                    unknown => {
                        return Err(format!("unknown flag for approve-grant: {unknown}").into());
                    }
                }
            }
            approve_grant_command(
                &proposal,
                &decision,
                &actor_id,
                reason,
                token_id,
                output.as_deref(),
            )?;
            Ok(ExitCode::SUCCESS)
        }
        "approve-grant-interactive" => {
            let proposal = required_arg(args.next(), "proposal json path")?;
            let actor_id = required_arg(args.next(), "actor id")?;
            let output = args.next();
            approve_grant_interactive_command(&proposal, &actor_id, output.as_deref())?;
            Ok(ExitCode::SUCCESS)
        }
        "revoke-token" => {
            let request_id = required_arg(args.next(), "request id")?;
            let token_id = required_arg(args.next(), "token id")?;
            let actor_id = required_arg(args.next(), "actor id")?;
            let mut reason: Option<String> = None;
            let mut output: Option<String> = None;
            while let Some(flag) = args.next() {
                match flag.as_str() {
                    "--reason" => {
                        reason = Some(required_arg(args.next(), "--reason value")?);
                    }
                    "--output" => {
                        output = Some(required_arg(args.next(), "--output value")?);
                    }
                    unknown => {
                        return Err(format!("unknown flag for revoke-token: {unknown}").into());
                    }
                }
            }
            revoke_token_command(&request_id, &token_id, &actor_id, reason, output.as_deref())?;
            Ok(ExitCode::SUCCESS)
        }
        "help" | "--help" | "-h" => {
            print_help();
            Ok(ExitCode::SUCCESS)
        }
        other => Err(format!("unknown command: {other}. Run `delegated-cli help`.").into()),
    }
}

fn sign_identity_command(
    input_path: &str,
    private_key_base64url: &str,
    output_path: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let mut identity: AgentIdentityDocument =
        serde_json::from_str(&fs::read_to_string(input_path)?)?;
    let signing_key = signing_key_from_base64url(private_key_base64url)?;
    identity.signature = sign_identity_document(&identity, &signing_key)?;
    write_json_output(&identity, output_path)?;
    Ok(())
}

fn sign_token_command(
    input_path: &str,
    private_key_base64url: &str,
    output_path: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let mut token: DelegationToken = serde_json::from_str(&fs::read_to_string(input_path)?)?;
    token.signature_alg = TOKEN_SIGNATURE_ALG_ED25519.to_string();
    let signing_key = signing_key_from_base64url(private_key_base64url)?;
    token.signature = sign_delegation_token(&token, &signing_key)?;
    write_json_output(&token, output_path)?;
    Ok(())
}

fn verify_request_command(input_path: &str) -> Result<ExitCode, Box<dyn Error>> {
    let raw: serde_json::Value = serde_json::from_str(&fs::read_to_string(input_path)?)?;
    let trust_state = FileBackedTrustState::new(default_trust_state_path());
    let (decision, _audit) = evaluate_request_with_state(
        &raw,
        Utc::now(),
        &trust_state,
        &delegated::HostContext::default(),
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "allowed": decision.allowed,
            "stage": decision.stage,
            "reason": decision.reason
        }))?
    );
    if decision.allowed {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(2))
    }
}

fn approve_grant_command(
    proposal_path: &str,
    decision_raw: &str,
    actor_id: &str,
    reason: Option<String>,
    token_id: Option<String>,
    output_path: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let proposal: DelegationGrantProposal =
        serde_json::from_str(&fs::read_to_string(proposal_path)?)?;
    let decision = parse_approval_decision(decision_raw)?;
    let operation = record_approval_decision(
        &proposal,
        decision,
        actor_id.to_string(),
        reason,
        Utc::now(),
        token_id,
    );
    let payload = json!({
        "grant_summary": render_cli_grant_summary(&proposal),
        "operation": operation
    });
    write_json_output(&payload, output_path)
}

fn approve_grant_interactive_command(
    proposal_path: &str,
    actor_id: &str,
    output_path: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let proposal: DelegationGrantProposal =
        serde_json::from_str(&fs::read_to_string(proposal_path)?)?;
    println!("{}", render_cli_grant_summary(&proposal));
    let decision_raw = prompt_line("Decision (approve|deny): ")?;
    let reason = prompt_optional_line("Reason (optional, press enter to skip): ")?;
    let token_id = if decision_raw == "approve" {
        prompt_optional_line("Token ID (optional, press enter to skip): ")?
    } else {
        None
    };
    approve_grant_command(
        proposal_path,
        &decision_raw,
        actor_id,
        reason,
        token_id,
        output_path,
    )
}

fn revoke_token_command(
    request_id: &str,
    token_id: &str,
    actor_id: &str,
    reason: Option<String>,
    output_path: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let trust_state = FileBackedTrustState::new(default_trust_state_path());
    let operation = revoke_token_with_receipt(
        &trust_state,
        request_id.to_string(),
        token_id.to_string(),
        actor_id.to_string(),
        reason,
        Utc::now(),
    )?;
    write_json_output(&operation, output_path)
}

fn parse_approval_decision(value: &str) -> Result<ApprovalDecision, Box<dyn Error>> {
    match value {
        "approve" => Ok(ApprovalDecision::Approve),
        "deny" => Ok(ApprovalDecision::Deny),
        _ => Err(format!("decision must be approve or deny, got: {value}").into()),
    }
}

fn required_arg(value: Option<String>, label: &str) -> Result<String, Box<dyn Error>> {
    value.ok_or_else(|| format!("missing required argument: {label}").into())
}

fn signing_key_from_base64url(private_key_base64url: &str) -> Result<SigningKey, Box<dyn Error>> {
    let bytes = Base64UrlUnpadded::decode_vec(private_key_base64url)
        .map_err(|_| "private key must be base64url-no-pad encoded")?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "private key must decode to 32 bytes for Ed25519")?;
    Ok(SigningKey::from_bytes(&key_bytes))
}

fn write_json_output<T: serde::Serialize>(
    value: &T,
    output_path: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let encoded = serde_json::to_string_pretty(value)?;
    if let Some(path) = output_path {
        if let Some(parent) = Path::new(path).parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, encoded)?;
    } else {
        println!("{encoded}");
    }
    Ok(())
}

fn prompt_line(label: &str) -> Result<String, Box<dyn Error>> {
    print!("{label}");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn prompt_optional_line(label: &str) -> Result<Option<String>, Box<dyn Error>> {
    let value = prompt_line(label)?;
    if value.is_empty() {
        return Ok(None);
    }
    Ok(Some(value))
}

fn print_help() {
    println!("delegated-cli");
    println!();
    println!("Commands:");
    println!("  sign-identity <input-json> <private-key-base64url> [output-json]");
    println!("  sign-token <input-json> <private-key-base64url> [output-json]");
    println!("  verify-request <input-json>");
    println!(
        "  approve-grant <proposal-json> <approve|deny> <actor-id> [--reason <text>] [--token-id <id>] [--output <path>]"
    );
    println!("  approve-grant-interactive <proposal-json> <actor-id> [output-json]");
    println!(
        "  revoke-token <request-id> <token-id> <actor-id> [--reason <text>] [--output <path>]"
    );
}
