//! CBOR processing for `WebAuthn`
//!
//! This module handles the CBOR (Concise Binary Object Representation)
//! processing needed for `WebAuthn` attestation and authenticator data.

use super::errors::WebAuthnError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ciborium::de::from_reader;
use ciborium::value::Value;

/// Extract public key from attestation
pub fn extract_public_key_from_attestation(
    attestation_object_b64: &str,
) -> Result<Vec<u8>, WebAuthnError> {
    // 1. Decode the base64 attestation object
    let attestation_bytes = URL_SAFE_NO_PAD
        .decode(attestation_object_b64)
        .map_err(|_| WebAuthnError::EncodingError("Invalid attestation encoding".to_string()))?;

    // 2. Parse CBOR
    let attestation: Value = from_reader(&attestation_bytes[..])
        .map_err(|_| WebAuthnError::EncodingError("Invalid CBOR attestation format".to_string()))?;

    // 3. Extract authData
    let Some(Some(auth_data)) = attestation.as_map().and_then(|map| {
        map.iter()
            .find(|(k, _)| k.as_text() == Some("authData"))
            .map(|(_, v)| v.as_bytes())
    }) else {
        return Err(WebAuthnError::EncodingError(
            "Missing authData in attestation".to_string(),
        ));
    };

    // 4. Parse auth_data (binary format)
    // The format is:
    // - 32 bytes: RP ID hash
    // - 1 byte: flags
    // - 4 bytes: signature counter
    // - variable: attested credential data (if flag UP bit is set)
    //   - 16 bytes: AAGUID
    //   - 2 bytes: credential ID length (L)
    //   - L bytes: credential ID
    //   - variable: COSE public key

    // Check flags (bit 6 must be set - attestedCredentialData present)
    if auth_data.len() < 37 {
        return Err(WebAuthnError::EncodingError(
            "Auth data too short".to_string(),
        ));
    }

    let flags = auth_data[32];
    if (flags & 0x40) == 0 {
        return Err(WebAuthnError::EncodingError(
            "No attested credential data".to_string(),
        ));
    }

    // Skip RP ID hash (32 bytes), flags (1 byte), counter (4 bytes)
    let mut pos = 37;

    // Skip AAGUID (16 bytes)
    pos += 16;

    // Get credential ID length
    if auth_data.len() < pos + 2 {
        return Err(WebAuthnError::EncodingError(
            "Auth data too short for credential ID length".to_string(),
        ));
    }

    let id_len = ((auth_data[pos] as usize) << 8) | (auth_data[pos + 1] as usize);
    pos += 2;

    // Skip credential ID
    pos += id_len;

    // The rest is the COSE public key
    if auth_data.len() <= pos {
        return Err(WebAuthnError::EncodingError(
            "Auth data too short for public key".to_string(),
        ));
    }

    let public_key = auth_data[pos..].to_vec();
    Ok(public_key)
}
