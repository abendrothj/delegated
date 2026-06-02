use agentauth::models::{AgentIdentityDocument, DelegationToken};
use agentauth::{
    TOKEN_SIGNATURE_ALG_ED25519, evaluate_request, sign_delegation_token, sign_identity_document,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::env;
use std::error::Error;
use std::fs;
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
        "help" | "--help" | "-h" => {
            print_help();
            Ok(ExitCode::SUCCESS)
        }
        other => Err(format!("unknown command: {other}. Run `agentauth-cli help`.").into()),
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
    let (decision, _audit) = evaluate_request(&raw, Utc::now());
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

fn print_help() {
    println!("agentauth-cli");
    println!();
    println!("Commands:");
    println!("  sign-identity <input-json> <private-key-base64url> [output-json]");
    println!("  sign-token <input-json> <private-key-base64url> [output-json]");
    println!("  verify-request <input-json>");
}
