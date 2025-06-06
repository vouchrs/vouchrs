//! `WebAuthn` attestation processing
//!
//! This module handles the attestation verification for `WebAuthn` operations.
//! It processes and verifies attestation statements from authenticators.

use super::cbor;
use super::errors::WebAuthnError;
use super::types::{Credential, RegistrationResponse};
use base64::Engine;
use chrono::Utc;

/// Extract and verify attestation information from registration response
///
/// # Arguments
/// * `response` - The `WebAuthn` registration response
/// * `expected_challenge` - The Base64URL-encoded challenge expected in client data
/// * `expected_origin` - The expected origin in client data
///
/// # Returns
/// * `Ok(Credential)` - The extracted credential with public key
/// * `Err(WebAuthnError)` - If attestation verification fails
pub fn verify_attestation(
    response: &RegistrationResponse,
    expected_challenge: &str,
    expected_origin: &str,
) -> Result<Credential, WebAuthnError> {
    // Extract and verify the client data (challenge, origin, type)
    verify_client_data(
        &response.response.client_data_json,
        "webauthn.create",
        expected_challenge,
        expected_origin,
    )?;

    // Extract public key from attestation
    let public_key =
        cbor::extract_public_key_from_attestation(&response.response.attestation_object)?;

    // Create the credential
    let credential = Credential {
        credential_id: response.id.clone(),
        user_handle: String::new(), // Set by caller
        public_key,
        counter: 0, // Initial counter value
        created_at: Utc::now(),
        last_used: None,
        name: None,
    };

    Ok(credential)
}

/// Verify client data JSON
///
/// # Arguments
/// * `client_data_json_b64` - Base64URL-encoded client data JSON
/// * `expected_type` - Expected type ("webauthn.create" or "webauthn.get")
/// * `expected_challenge` - Expected challenge
/// * `expected_origin` - Expected origin
///
/// # Returns
/// * `Ok(())` - If client data is valid
/// * `Err(WebAuthnError)` - If client data is invalid
pub fn verify_client_data(
    client_data_json_b64: &str,
    expected_type: &str,
    expected_challenge: &str,
    expected_origin: &str,
) -> Result<(), WebAuthnError> {
    // Decode and parse client data
    let client_data_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(client_data_json_b64)
        .map_err(|_| WebAuthnError::EncodingError("Invalid client data encoding".to_string()))?;

    let client_data: serde_json::Value = serde_json::from_slice(&client_data_bytes)
        .map_err(|_| WebAuthnError::EncodingError("Invalid client data JSON".to_string()))?;

    // Verify type
    let Some(type_val) = client_data.get("type") else {
        return Err(WebAuthnError::VerificationFailed(
            "Missing type in client data".to_string(),
        ));
    };

    if type_val.as_str() != Some(expected_type) {
        return Err(WebAuthnError::VerificationFailed(format!(
            "Invalid type, expected {expected_type}"
        )));
    }

    // Verify challenge
    let Some(challenge_val) = client_data.get("challenge") else {
        return Err(WebAuthnError::VerificationFailed(
            "Missing challenge in client data".to_string(),
        ));
    };

    if challenge_val.as_str() != Some(expected_challenge) {
        return Err(WebAuthnError::VerificationFailed(
            "Challenge mismatch".to_string(),
        ));
    }

    // Verify origin
    let Some(origin_val) = client_data.get("origin") else {
        return Err(WebAuthnError::VerificationFailed(
            "Missing origin in client data".to_string(),
        ));
    };

    if origin_val.as_str() != Some(expected_origin) {
        return Err(WebAuthnError::VerificationFailed(
            "Origin mismatch".to_string(),
        ));
    }

    Ok(())
}
