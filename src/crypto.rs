use crate::models::{AgentIdentityDocument, DelegationToken, Violation};
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub const TOKEN_SIGNATURE_ALG_ED25519: &str = "Ed25519";
pub const SIGNATURE_ENCODING_BASE64URL_NO_PAD: &str = "base64url-no-pad";
pub const SIGNATURE_WIRE_FORMAT: &str = "delegated.detached-json.v1";

const STAGE: &str = "verify_signatures";

pub fn sign_identity_document(
    document: &AgentIdentityDocument,
    signing_key: &SigningKey,
) -> Result<String, Violation> {
    let payload = canonical_identity_payload(document)?;
    let signature = signing_key.sign(&payload);
    Ok(Base64UrlUnpadded::encode_string(&signature.to_bytes()))
}

pub fn sign_delegation_token(
    token: &DelegationToken,
    signing_key: &SigningKey,
) -> Result<String, Violation> {
    let payload = canonical_token_payload(token)?;
    let signature = signing_key.sign(&payload);
    Ok(Base64UrlUnpadded::encode_string(&signature.to_bytes()))
}

pub fn verify_identity_document_signature(
    document: &AgentIdentityDocument,
) -> Result<(), Violation> {
    let payload = canonical_identity_payload(document)?;
    let signature = decode_signature(&document.signature, "identity_document.signature")?;

    let mut key_parse_failures = 0usize;
    for key in &document.public_keys {
        let verifying_key = match verifying_key_from_public_material(
            key.x.as_deref(),
            key.kty.as_str(),
            key.crv.as_deref(),
            "identity_document.public_keys",
        ) {
            Ok(parsed) => parsed,
            Err(_) => {
                key_parse_failures += 1;
                continue;
            }
        };

        if verifying_key.verify(&payload, &signature).is_ok() {
            return Ok(());
        }
    }

    if key_parse_failures == document.public_keys.len() {
        return Err(Violation::new(
            STAGE,
            "identity document does not contain a usable Ed25519 public key",
        ));
    }

    Err(Violation::new(
        STAGE,
        "identity document signature verification failed for all keys",
    ))
}

pub fn verify_delegation_token_signature(
    token: &DelegationToken,
    identity_document: &AgentIdentityDocument,
) -> Result<(), Violation> {
    if token.signature_alg != TOKEN_SIGNATURE_ALG_ED25519 {
        return Err(Violation::new(
            STAGE,
            format!(
                "delegation token signature_alg must be {}",
                TOKEN_SIGNATURE_ALG_ED25519
            ),
        ));
    }

    let key = identity_document
        .public_keys
        .iter()
        .find(|public_key| public_key.kid == token.key_id)
        .ok_or_else(|| {
            Violation::new(
                STAGE,
                "delegation token key_id does not match an identity document public key",
            )
        })?;

    let verifying_key = verifying_key_from_public_material(
        key.x.as_deref(),
        key.kty.as_str(),
        key.crv.as_deref(),
        "delegation_token.key_id",
    )?;
    let payload = canonical_token_payload(token)?;
    let signature = decode_signature(&token.signature, "delegation_token.signature")?;

    verifying_key.verify(&payload, &signature).map_err(|_| {
        Violation::new(
            STAGE,
            "delegation token signature verification failed for selected key_id",
        )
    })
}

/// Produces a deterministic JSON byte representation with object keys sorted alphabetically.
/// This is the canonical form used for signature payloads, ensuring cross-language interoperability.
fn canonical_json(value: &serde_json::Value) -> Vec<u8> {
    let mut buf = Vec::new();
    write_canonical(&mut buf, value);
    buf
}

fn write_canonical(buf: &mut Vec<u8>, value: &serde_json::Value) {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            buf.push(b'{');
            let mut entries: Vec<(&String, &serde_json::Value)> = map.iter().collect();
            entries.sort_by_key(|(k, _)| k.as_str());
            for (i, (key, val)) in entries.iter().enumerate() {
                if i > 0 {
                    buf.push(b',');
                }
                buf.extend_from_slice(
                    serde_json::to_string(key)
                        .expect("key serialization must succeed")
                        .as_bytes(),
                );
                buf.push(b':');
                write_canonical(buf, val);
            }
            buf.push(b'}');
        }
        Value::Array(arr) => {
            buf.push(b'[');
            for (i, val) in arr.iter().enumerate() {
                if i > 0 {
                    buf.push(b',');
                }
                write_canonical(buf, val);
            }
            buf.push(b']');
        }
        _ => {
            buf.extend_from_slice(
                serde_json::to_string(value)
                    .expect("value serialization must succeed")
                    .as_bytes(),
            );
        }
    }
}

fn canonical_identity_payload(document: &AgentIdentityDocument) -> Result<Vec<u8>, Violation> {
    let mut unsigned = document.clone();
    unsigned.signature.clear();
    let value = serde_json::to_value(&unsigned).map_err(|err| {
        Violation::new(
            STAGE,
            format!("failed to serialize identity document for signature payload: {err}"),
        )
    })?;
    Ok(canonical_json(&value))
}

fn canonical_token_payload(token: &DelegationToken) -> Result<Vec<u8>, Violation> {
    let mut unsigned = token.clone();
    unsigned.signature.clear();
    let value = serde_json::to_value(&unsigned).map_err(|err| {
        Violation::new(
            STAGE,
            format!("failed to serialize delegation token for signature payload: {err}"),
        )
    })?;
    Ok(canonical_json(&value))
}

fn decode_signature(raw: &str, field_name: &str) -> Result<Signature, Violation> {
    let bytes = Base64UrlUnpadded::decode_vec(raw).map_err(|_| {
        Violation::new(
            STAGE,
            format!("{field_name} must be base64url-no-pad encoded"),
        )
    })?;
    let raw_signature: [u8; 64] = bytes.try_into().map_err(|_| {
        Violation::new(
            STAGE,
            format!("{field_name} must decode to 64 bytes for Ed25519"),
        )
    })?;
    Ok(Signature::from_bytes(&raw_signature))
}

fn verifying_key_from_public_material(
    encoded_public_key: Option<&str>,
    kty: &str,
    crv: Option<&str>,
    field_name: &str,
) -> Result<VerifyingKey, Violation> {
    if kty != "OKP" {
        return Err(Violation::new(
            STAGE,
            format!("{field_name} must use kty=OKP for Ed25519 verification"),
        ));
    }
    if crv != Some(TOKEN_SIGNATURE_ALG_ED25519) {
        return Err(Violation::new(
            STAGE,
            format!(
                "{field_name} must use crv={} for Ed25519 verification",
                TOKEN_SIGNATURE_ALG_ED25519
            ),
        ));
    }
    let encoded = encoded_public_key.ok_or_else(|| {
        Violation::new(
            STAGE,
            format!("{field_name} must include public key material in x"),
        )
    })?;
    let bytes = Base64UrlUnpadded::decode_vec(encoded).map_err(|_| {
        Violation::new(
            STAGE,
            format!("{field_name}.x must be base64url-no-pad encoded"),
        )
    })?;
    let raw_key: [u8; 32] = bytes.try_into().map_err(|_| {
        Violation::new(
            STAGE,
            format!("{field_name}.x must decode to 32 bytes for Ed25519"),
        )
    })?;
    VerifyingKey::from_bytes(&raw_key).map_err(|_| {
        Violation::new(
            STAGE,
            format!("{field_name}.x is not a valid Ed25519 public key"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        AgentEndpoint, AttestationRecord, MaxSpend, PublicKeyRecord, ResourceConstraints,
    };
    use chrono::{TimeZone, Utc};

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn sample_identity() -> AgentIdentityDocument {
        let key = signing_key().verifying_key();
        AgentIdentityDocument {
            spec_version: "0.1".to_string(),
            kind: "AgentIdentityDocument".to_string(),
            agent_id: "agent:example:scheduler:v1".to_string(),
            display_name: Some("Scheduler Agent".to_string()),
            owner_id: "org:example".to_string(),
            issuer: "https://trust.example.ai".to_string(),
            identity_type: "spiffe".to_string(),
            subject: "spiffe://example.ai/agents/scheduler".to_string(),
            public_keys: vec![PublicKeyRecord {
                kid: "key-2026-01".to_string(),
                kty: "OKP".to_string(),
                crv: Some(TOKEN_SIGNATURE_ALG_ED25519.to_string()),
                x: Some(Base64UrlUnpadded::encode_string(&key.to_bytes())),
            }],
            supported_protocols: vec!["http".to_string()],
            supported_auth_methods: vec!["delegation_token".to_string()],
            capabilities: Some(vec!["schedule_meeting".to_string()]),
            endpoints: vec![AgentEndpoint {
                protocol: "http".to_string(),
                url: "https://agents.example.ai/scheduler".to_string(),
            }],
            attestation: Some(AttestationRecord {
                type_name: "workload".to_string(),
                issuer: "spire://example".to_string(),
                evidence_ref: "urn:attest:spire:cluster-a".to_string(),
            }),
            created_at: Utc
                .with_ymd_and_hms(2026, 6, 1, 20, 0, 0)
                .single()
                .expect("valid timestamp"),
            expires_at: Utc
                .with_ymd_and_hms(2026, 6, 8, 20, 0, 0)
                .single()
                .expect("valid timestamp"),
            signature: String::new(),
        }
    }

    fn sample_token() -> DelegationToken {
        DelegationToken {
            spec_version: "0.1".to_string(),
            kind: "DelegationToken".to_string(),
            token_id: "dlg_01J0EXAMPLE".to_string(),
            issuer: "https://trust.example.ai".to_string(),
            agent_id: "agent:example:scheduler:v1".to_string(),
            delegator_id: "user:jake-abendroth".to_string(),
            owner_id: "org:example".to_string(),
            audience: vec!["tool:google-calendar".to_string()],
            allowed_actions: vec!["calendar.create_event".to_string()],
            resource_constraints: Some(ResourceConstraints {
                calendar_ids: Some(vec!["primary".to_string()]),
                email_domain_allowlist: Some(vec!["example.com".to_string()]),
                extra: Default::default(),
            }),
            max_spend: Some(MaxSpend {
                amount: 0,
                currency: "USD".to_string(),
            }),
            max_delegation_depth: Some(0),
            issued_at: Utc
                .with_ymd_and_hms(2026, 6, 1, 20, 10, 0)
                .single()
                .expect("valid timestamp"),
            expires_at: Utc
                .with_ymd_and_hms(2026, 6, 1, 20, 40, 0)
                .single()
                .expect("valid timestamp"),
            intent: Some("schedule_demo_and_send_confirmation".to_string()),
            nonce: "random-nonce".to_string(),
            key_id: "key-2026-01".to_string(),
            signature_alg: TOKEN_SIGNATURE_ALG_ED25519.to_string(),
            signature: String::new(),
        }
    }

    #[test]
    fn signs_and_verifies_identity_document() {
        let key = signing_key();
        let mut identity = sample_identity();
        identity.signature = sign_identity_document(&identity, &key).expect("signing should work");
        verify_identity_document_signature(&identity).expect("verification should work");
    }

    #[test]
    fn signs_and_verifies_delegation_token() {
        let key = signing_key();
        let mut identity = sample_identity();
        identity.signature = sign_identity_document(&identity, &key).expect("signing should work");

        let mut token = sample_token();
        token.signature = sign_delegation_token(&token, &key).expect("signing should work");
        verify_delegation_token_signature(&token, &identity).expect("verification should work");
    }
}
