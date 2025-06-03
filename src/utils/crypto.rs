// Cryptographic utilities for generating secure tokens and nonces

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use serde::{de::DeserializeOwned, Serialize};

/// Nonce size for AES-256-GCM encryption (96 bits)
pub const NONCE_SIZE: usize = 12;

/// Encryption key size for AES-256 (256 bits)
pub const ENCRYPTION_KEY_SIZE: usize = 32;

/// Generate a cryptographically secure CSRF token
///
/// This generates a more compact token with higher entropy than UUID v4:
/// - 24 bytes (192 bits) of entropy vs UUID's 122 bits
/// - `Base64URL` encoding results in 32 characters vs UUID's 36 characters
/// - Uses the same secure random source as our AES-GCM encryption
///
/// Inspired by oauth2-proxy's approach but optimized for URL length
///
/// # Returns
///
/// A base64url-encoded string representing 24 bytes of cryptographically secure random data
#[must_use]
pub fn generate_csrf_token() -> String {
    let mut nonce = [0u8; 24]; // 192 bits of entropy
    rand::rng().fill_bytes(&mut nonce);
    general_purpose::URL_SAFE_NO_PAD.encode(nonce)
}

/// Generate a cryptographically secure nonce of specified byte length
///
/// This is a more general-purpose function for generating secure random data
///
/// # Arguments
///
/// * `length` - Number of bytes to generate (recommended: 16-32 for most use cases)
///
/// # Returns
///
/// A base64url-encoded string representing the specified bytes of random data
#[must_use]
pub fn generate_nonce(length: usize) -> String {
    let mut nonce = vec![0u8; length];
    rand::rng().fill_bytes(&mut nonce);
    general_purpose::URL_SAFE_NO_PAD.encode(nonce)
}

/// Helper function to decode JWT token payload without verification
/// This is used for debugging purposes only to inspect token claims
///
/// # Errors
///
/// Returns an error if:
/// - The JWT format is invalid (not 3 parts separated by dots)
/// - Base64 decoding fails
/// - UTF-8 decoding fails
/// - JSON parsing fails
pub fn decode_jwt_payload(token: &str) -> Result<serde_json::Value, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT format".to_string());
    }

    let payload_b64 = parts[1];
    let payload_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .or_else(|_| general_purpose::STANDARD.decode(payload_b64))
        .map_err(|_| "Base64 decode failed")?;

    let payload_str = String::from_utf8(payload_bytes).map_err(|_| "UTF-8 decode failed")?;

    serde_json::from_str(&payload_str).map_err(|_| "JSON parse failed".to_string())
}

/// Generic encryption function for any serializable data using AES-256-GCM
///
/// # Arguments
///
/// * `data` - The data to encrypt (must implement Serialize)
/// * `key` - The encryption key (must be 32 bytes for AES-256)
///
/// # Returns
///
/// A Base64URL-encoded string containing the nonce + ciphertext
///
/// # Errors
///
/// Returns an error if:
/// - Serialization fails
/// - Key length is invalid
/// - AES encryption fails
pub fn encrypt_data<T: Serialize>(data: &T, key: &[u8]) -> Result<String> {
    if key.len() != ENCRYPTION_KEY_SIZE {
        return Err(anyhow!(
            "Invalid key length: expected {} bytes, got {}",
            ENCRYPTION_KEY_SIZE,
            key.len()
        ));
    }

    // Serialize the data to JSON
    let json_data = serde_json::to_string(data).context("Failed to serialize data")?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the data
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let ciphertext = cipher
        .encrypt(nonce, json_data.as_bytes())
        .map_err(|e| anyhow!("AES encryption failed: {e}"))?;

    // Combine nonce + ciphertext and encode as base64
    let mut combined = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    Ok(general_purpose::URL_SAFE_NO_PAD.encode(&combined))
}

/// Generic decryption function for any deserializable data using AES-256-GCM
///
/// # Arguments
///
/// * `encrypted_data` - Base64URL-encoded string containing nonce + ciphertext
/// * `key` - The decryption key (must be 32 bytes for AES-256)
///
/// # Returns
///
/// The decrypted and deserialized data
///
/// # Errors
///
/// Returns an error if:
/// - Key length is invalid
/// - Base64 decoding fails
/// - Data length is invalid
/// - AES decryption fails
/// - Deserialization fails
pub fn decrypt_data<T: DeserializeOwned>(encrypted_data: &str, key: &[u8]) -> Result<T> {
    if key.len() != ENCRYPTION_KEY_SIZE {
        return Err(anyhow!(
            "Invalid key length: expected {} bytes, got {}",
            ENCRYPTION_KEY_SIZE,
            key.len()
        ));
    }

    // Decode from base64
    let combined = general_purpose::URL_SAFE_NO_PAD
        .decode(encrypted_data)
        .context("Failed to decode base64 data")?;

    if combined.len() < NONCE_SIZE {
        return Err(anyhow!("Invalid data length"));
    }

    // Split nonce and ciphertext
    let (nonce_bytes, ciphertext) = combined.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt the data
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("AES decryption failed: {e}"))?;

    // Deserialize the data from JSON
    let data: T = serde_json::from_slice(&plaintext)
        .context("Failed to deserialize data from decrypted JSON")?;

    Ok(data)
}

/// Derive a proper 32-byte encryption key from input key material
///
/// This function ensures that any input key is properly extended or truncated
/// to exactly 32 bytes for use with AES-256. For keys shorter than 32 bytes,
/// it uses a simple hash-based extension method.
///
/// # Arguments
///
/// * `input_key` - The input key material (any length)
///
/// # Returns
///
/// A 32-byte encryption key suitable for AES-256
///
/// # Note
///
/// This is a simple key derivation method. For production use with weak keys,
/// consider using proper key derivation functions like PBKDF2 or HKDF.
#[must_use]
pub fn derive_encryption_key(input_key: &[u8]) -> [u8; ENCRYPTION_KEY_SIZE] {
    let mut encryption_key = [0u8; ENCRYPTION_KEY_SIZE];
    let key_len = std::cmp::min(input_key.len(), ENCRYPTION_KEY_SIZE);
    encryption_key[..key_len].copy_from_slice(&input_key[..key_len]);

    // If key is shorter than 32 bytes, derive the rest using a simple hash
    if key_len < ENCRYPTION_KEY_SIZE {
        for i in key_len..ENCRYPTION_KEY_SIZE {
            encryption_key[i] =
                encryption_key[i % key_len].wrapping_add(u8::try_from(i % 256).unwrap_or(0));
        }
    }

    encryption_key
}

/// JWT signing algorithms supported by the generic JWT functions
#[derive(Debug, Clone, Copy)]
pub enum JwtAlgorithm {
    /// HMAC with SHA-256 (symmetric key)
    HS256,
    /// ECDSA with P-256 curve and SHA-256 (asymmetric key)
    ES256,
}

/// Generic JWT creation function for different signing algorithms
///
/// This function supports both HMAC-SHA256 (HS256) and ECDSA P-256 (ES256) signing.
///
/// # Arguments
///
/// * `header` - JWT header as a JSON value
/// * `payload` - JWT payload/claims as a JSON value  
/// * `algorithm` - The signing algorithm to use
/// * `key_material` - Key material for signing:
///   - For HS256: The shared secret as bytes
///   - For ES256: PEM-encoded PKCS#8 private key as string
///
/// # Returns
///
/// A complete JWT string with header.payload.signature
///
/// # Errors
///
/// Returns an error if:
/// - JSON serialization fails
/// - Key parsing fails (for ES256)
/// - Signing operation fails
/// - Base64 encoding fails
pub fn create_jwt(
    header: &serde_json::Value,
    payload: &serde_json::Value,
    algorithm: JwtAlgorithm,
    key_material: &[u8],
) -> Result<String> {
    // Serialize header and payload
    let header_json = serde_json::to_string(header).context("Failed to serialize JWT header")?;
    let payload_json = serde_json::to_string(payload).context("Failed to serialize JWT payload")?;

    // Base64URL encode header and payload
    let header_b64 = general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    let payload_b64 = general_purpose::URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

    let message = format!("{header_b64}.{payload_b64}");

    // Sign the message based on algorithm
    let signature_bytes = match algorithm {
        JwtAlgorithm::HS256 => sign_jwt_hmac_sha256(message.as_bytes(), key_material)?,
        JwtAlgorithm::ES256 => {
            let key_pem = std::str::from_utf8(key_material)
                .context("ES256 key material must be valid UTF-8 PEM")?;
            sign_jwt_es256(message.as_bytes(), key_pem)?
        }
    };

    let signature_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&signature_bytes);

    Ok(format!("{message}.{signature_b64}"))
}

/// Sign a message using HMAC-SHA256
///
/// # Arguments
///
/// * `message` - The message to sign
/// * `secret` - The shared secret key
///
/// # Returns
///
/// The HMAC-SHA256 signature as bytes
///
/// # Errors
///
/// Returns an error if HMAC computation fails
fn sign_jwt_hmac_sha256(message: &[u8], secret: &[u8]) -> Result<Vec<u8>> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret).context("Invalid HMAC key length")?;
    mac.update(message);

    Ok(mac.finalize().into_bytes().to_vec())
}

/// Sign a message using ECDSA P-256 with SHA-256 (ES256)
///
/// # Arguments
///
/// * `message` - The message to sign
/// * `private_key_pem` - PEM-encoded PKCS#8 private key
///
/// # Returns
///
/// The ES256 signature as bytes
///
/// # Errors
///
/// Returns an error if:
/// - Private key parsing fails
/// - Signing operation fails
fn sign_jwt_es256(message: &[u8], private_key_pem: &str) -> Result<Vec<u8>> {
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use p256::pkcs8::DecodePrivateKey;

    let signing_key = SigningKey::from_pkcs8_pem(private_key_pem)
        .map_err(|e| anyhow!("Failed to parse ECDSA private key: {e:?}"))?;

    let signature: Signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

/// Helper function to create JWT header for common algorithms
///
/// # Arguments
///
/// * `algorithm` - The JWT algorithm
/// * `key_id` - Optional key ID (for ES256 with key rotation)
///
/// # Returns
///
/// A JSON value representing the JWT header
#[must_use]
pub fn create_jwt_header(algorithm: &JwtAlgorithm, key_id: Option<&str>) -> serde_json::Value {
    let alg_str = match algorithm {
        JwtAlgorithm::HS256 => "HS256",
        JwtAlgorithm::ES256 => "ES256",
    };

    let mut header = serde_json::json!({
        "alg": alg_str,
        "typ": "JWT"
    });

    if let Some(kid) = key_id {
        header["kid"] = serde_json::Value::String(kid.to_string());
    }

    header
}

/// Helper function to create standard JWT payload with common claims
///
/// # Arguments
///
/// * `issuer` - The issuer (iss) claim
/// * `subject` - The subject (sub) claim  
/// * `audience` - The audience (aud) claim
/// * `expiry_minutes` - Token expiry time in minutes from now
/// * `additional_claims` - Additional custom claims to include
///
/// # Returns
///
/// A JSON value representing the JWT payload
#[must_use]
pub fn create_jwt_payload(
    issuer: &str,
    subject: &str,
    audience: &str,
    expiry_minutes: i64,
    additional_claims: Option<&serde_json::Value>,
) -> serde_json::Value {
    use chrono::{Duration, Utc};

    let now = Utc::now();
    let exp = now + Duration::minutes(expiry_minutes);

    let mut payload = serde_json::json!({
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "iat": now.timestamp(),
        "exp": exp.timestamp()
    });

    // Merge additional claims if provided
    if let Some(serde_json::Value::Object(additional_map)) = additional_claims {
        if let serde_json::Value::Object(ref mut payload_map) = payload {
            for (key, value) in additional_map {
                payload_map.insert(key.clone(), value.clone());
            }
        }
    }

    payload
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Test secret key for HMAC operations - generated dynamically
    fn get_test_secret() -> Vec<u8> {
        b"test_secret_key_for_hmac_testing_32b".to_vec()
    }

    // Generate a new test P-256 private key for ES256 testing
    // This dynamically creates a new key each time for testing purposes
    fn generate_test_es256_key() -> String {
        use p256::pkcs8::EncodePrivateKey;
        use p256::SecretKey;

        // Generate a new random P-256 secret key
        let secret_key = SecretKey::random(&mut rand::rng());

        // Encode as PKCS#8 PEM format and extract the string from Zeroizing wrapper
        secret_key
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .expect("Failed to encode private key as PKCS#8 PEM")
            .to_string()
    }

    #[test]
    fn test_create_jwt_header_hs256() {
        let header = create_jwt_header(&JwtAlgorithm::HS256, None);

        assert_eq!(header["alg"], "HS256");
        assert_eq!(header["typ"], "JWT");
        assert!(header.get("kid").is_none());
    }

    #[test]
    fn test_create_jwt_header_es256_with_kid() {
        let header = create_jwt_header(&JwtAlgorithm::ES256, Some("test-key-id"));

        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["kid"], "test-key-id");
    }

    #[test]
    fn test_create_jwt_payload() {
        let payload = create_jwt_payload(
            "test-issuer",
            "test-subject",
            "test-audience",
            60, // 1 hour
            None,
        );

        assert_eq!(payload["iss"], "test-issuer");
        assert_eq!(payload["sub"], "test-subject");
        assert_eq!(payload["aud"], "test-audience");
        assert!(payload["iat"].is_number());
        assert!(payload["exp"].is_number());

        // Verify expiry is 1 hour from now
        let iat = payload["iat"].as_i64().unwrap();
        let exp = payload["exp"].as_i64().unwrap();
        assert_eq!(exp - iat, 3600); // 60 minutes * 60 seconds
    }

    #[test]
    fn test_create_jwt_payload_with_additional_claims() {
        let additional_claims = json!({
            "custom_field": "custom_value",
            "number_field": 123
        });

        let payload = create_jwt_payload(
            "test-issuer",
            "test-subject",
            "test-audience",
            5,
            Some(&additional_claims),
        );

        assert_eq!(payload["iss"], "test-issuer");
        assert_eq!(payload["custom_field"], "custom_value");
        assert_eq!(payload["number_field"], 123);
    }

    #[test]
    fn test_hmac_sha256_signing() {
        let test_secret = get_test_secret();
        let message = b"test.message";
        let result = sign_jwt_hmac_sha256(message, &test_secret);

        assert!(result.is_ok());
        let signature = result.unwrap();
        assert!(!signature.is_empty());
        assert_eq!(signature.len(), 32); // SHA-256 produces 32-byte hash
    }

    #[test]
    fn test_hmac_sha256_deterministic() {
        let message = b"test.message";
        let test_secret = get_test_secret();

        let sig1 = sign_jwt_hmac_sha256(message, &test_secret).unwrap();
        let sig2 = sign_jwt_hmac_sha256(message, &test_secret).unwrap();

        assert_eq!(sig1, sig2, "HMAC signatures should be deterministic");
    }

    #[test]
    fn test_hmac_sha256_different_messages() {
        let message1 = b"test.message1";
        let message2 = b"test.message2";
        let test_secret = get_test_secret();

        let sig1 = sign_jwt_hmac_sha256(message1, &test_secret).unwrap();
        let sig2 = sign_jwt_hmac_sha256(message2, &test_secret).unwrap();

        assert_ne!(
            sig1, sig2,
            "Different messages should produce different signatures"
        );
    }

    #[test]
    fn test_create_jwt_hs256() {
        let header = create_jwt_header(&JwtAlgorithm::HS256, None);
        let payload = json!({
            "sub": "test-user",
            "iat": 1_234_567_890,
            "exp": 1_234_571_490
        });

        let test_secret = get_test_secret();
        let result = create_jwt(&header, &payload, JwtAlgorithm::HS256, &test_secret);

        assert!(result.is_ok());
        let jwt = result.unwrap();

        // JWT should have 3 parts separated by dots
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Decode and verify header
        let header_bytes = general_purpose::URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let decoded_header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(decoded_header["alg"], "HS256");
        assert_eq!(decoded_header["typ"], "JWT");

        // Decode and verify payload
        let payload_bytes = general_purpose::URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let decoded_payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(decoded_payload["sub"], "test-user");
        assert_eq!(decoded_payload["iat"], 1_234_567_890);
        assert_eq!(decoded_payload["exp"], 1_234_571_490);
    }

    #[test]
    fn test_create_jwt_hs256_verification() {
        let header = create_jwt_header(&JwtAlgorithm::HS256, None);
        let payload = json!({
            "sub": "test-user",
            "iss": "test-issuer"
        });

        let test_secret = get_test_secret();
        let jwt = create_jwt(&header, &payload, JwtAlgorithm::HS256, &test_secret).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();

        // Manually verify HMAC signature
        let message = format!("{}.{}", parts[0], parts[1]);
        let expected_signature = sign_jwt_hmac_sha256(message.as_bytes(), &test_secret).unwrap();
        let expected_signature_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&expected_signature);

        assert_eq!(parts[2], expected_signature_b64);
    }

    #[test]
    fn test_es256_signing_deterministic_within_same_key() {
        // ES256 produces different signatures each time (due to random k value),
        // but we should be able to sign successfully
        let message = b"test.message";

        // Generate a test key for this test
        let test_es256_key = generate_test_es256_key();

        let result1 = sign_jwt_es256(message, &test_es256_key);
        let result2 = sign_jwt_es256(message, &test_es256_key);

        assert!(result1.is_ok());
        assert!(result2.is_ok());

        let sig1 = result1.unwrap();
        let sig2 = result2.unwrap();

        // ES256 signatures are not deterministic due to random k value
        // But they should both be 64 bytes (32 bytes r + 32 bytes s)
        assert_eq!(sig1.len(), 64);
        assert_eq!(sig2.len(), 64);
    }

    #[test]
    fn test_create_jwt_es256() {
        let header = create_jwt_header(&JwtAlgorithm::ES256, Some("test-key"));
        let payload = json!({
            "sub": "test-user",
            "iss": "test-issuer",
            "aud": "https://api.example.com"
        });

        // Generate a key for this test
        let test_es256_key = generate_test_es256_key();
        let result = create_jwt(
            &header,
            &payload,
            JwtAlgorithm::ES256,
            test_es256_key.as_bytes(),
        );

        assert!(result.is_ok());
        let jwt = result.unwrap();

        // JWT should have 3 parts separated by dots
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Decode and verify header
        let header_bytes = general_purpose::URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let decoded_header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(decoded_header["alg"], "ES256");
        assert_eq!(decoded_header["typ"], "JWT");
        assert_eq!(decoded_header["kid"], "test-key");

        // Decode and verify payload
        let payload_bytes = general_purpose::URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let decoded_payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(decoded_payload["sub"], "test-user");
        assert_eq!(decoded_payload["iss"], "test-issuer");
        assert_eq!(decoded_payload["aud"], "https://api.example.com");

        // Signature should be base64url encoded and non-empty
        assert!(!parts[2].is_empty());
        let signature_bytes = general_purpose::URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        assert_eq!(signature_bytes.len(), 64); // ES256 signature is 64 bytes
    }

    #[test]
    fn test_create_jwt_invalid_es256_key() {
        let header = create_jwt_header(&JwtAlgorithm::ES256, None);
        let payload = json!({"sub": "test"});
        let invalid_key = b"not-a-valid-pem-key";

        let result = create_jwt(&header, &payload, JwtAlgorithm::ES256, invalid_key);

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error
            .to_string()
            .contains("Failed to parse ECDSA private key"));
    }

    #[test]
    fn test_create_jwt_malformed_es256_key() {
        let header = create_jwt_header(&JwtAlgorithm::ES256, None);
        let payload = json!({"sub": "test"});
        let malformed_key = "-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----";

        let result = create_jwt(
            &header,
            &payload,
            JwtAlgorithm::ES256,
            malformed_key.as_bytes(),
        );

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error
            .to_string()
            .contains("Failed to parse ECDSA private key"));
    }

    #[test]
    fn test_hmac_invalid_key_length() {
        // Test with zero-length key (should still work with HMAC)
        let message = b"test.message";
        let empty_key = b"";

        let result = sign_jwt_hmac_sha256(message, empty_key);
        // HMAC should work with any key length, including empty
        assert!(result.is_ok());
    }

    #[test]
    fn test_jwt_algorithm_debug() {
        // Test that the enum implements Debug properly
        let hs256 = JwtAlgorithm::HS256;
        let es256 = JwtAlgorithm::ES256;

        assert!(format!("{hs256:?}").contains("HS256"));
        assert!(format!("{es256:?}").contains("ES256"));
    }

    #[test]
    fn test_jwt_algorithm_clone() {
        // Test that the enum implements Clone properly
        let original = JwtAlgorithm::HS256;
        let cloned = original;

        // They should be equal (though we can't test equality directly without PartialEq)
        assert!(format!("{original:?}") == format!("{cloned:?}"));
    }

    #[test]
    fn test_empty_jwt_payload() {
        let header = create_jwt_header(&JwtAlgorithm::HS256, None);
        let payload = json!({});

        let test_secret = get_test_secret();
        let result = create_jwt(&header, &payload, JwtAlgorithm::HS256, &test_secret);

        assert!(result.is_ok());
        let jwt = result.unwrap();

        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Should be able to decode empty payload
        let payload_bytes = general_purpose::URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let decoded_payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert!(decoded_payload.is_object());
        assert!(decoded_payload.as_object().unwrap().is_empty());
    }

    #[test]
    fn test_large_jwt_payload() {
        let header = create_jwt_header(&JwtAlgorithm::HS256, None);
        let large_string = "x".repeat(1000);
        let payload = json!({
            "large_field": large_string,
            "sub": "test-user"
        });

        let test_secret = get_test_secret();
        let result = create_jwt(&header, &payload, JwtAlgorithm::HS256, &test_secret);

        assert!(result.is_ok());
        let jwt = result.unwrap();

        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Should be able to decode large payload
        let payload_bytes = general_purpose::URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let decoded_payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(decoded_payload["sub"], "test-user");
        assert_eq!(decoded_payload["large_field"], large_string);
    }

    #[test]
    fn test_generate_test_es256_key_produces_different_keys() {
        // Generate multiple keys and verify they are all different
        let key1 = generate_test_es256_key();
        let key2 = generate_test_es256_key();
        let key3 = generate_test_es256_key();

        // All keys should be valid PKCS#8 PEM format
        assert!(key1.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(key1.trim_end().ends_with("-----END PRIVATE KEY-----"));
        assert!(key2.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(key2.trim_end().ends_with("-----END PRIVATE KEY-----"));
        assert!(key3.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(key3.trim_end().ends_with("-----END PRIVATE KEY-----"));

        // Each key should be different (randomness test)
        assert_ne!(key1, key2, "First and second keys should be different");
        assert_ne!(key2, key3, "Second and third keys should be different");
        assert_ne!(key1, key3, "First and third keys should be different");

        // Each key should be able to create valid JWTs
        let header = create_jwt_header(&JwtAlgorithm::ES256, Some("test-key"));
        let payload = json!({"sub": "test-user", "iss": "test-issuer"});

        let jwt1 = create_jwt(&header, &payload, JwtAlgorithm::ES256, key1.as_bytes()).unwrap();
        let jwt2 = create_jwt(&header, &payload, JwtAlgorithm::ES256, key2.as_bytes()).unwrap();
        let jwt3 = create_jwt(&header, &payload, JwtAlgorithm::ES256, key3.as_bytes()).unwrap();

        // All JWTs should be valid (3 parts)
        assert_eq!(jwt1.split('.').count(), 3);
        assert_eq!(jwt2.split('.').count(), 3);
        assert_eq!(jwt3.split('.').count(), 3);

        // JWTs created with different keys should have different signatures
        let sig1 = jwt1.split('.').nth(2).unwrap();
        let sig2 = jwt2.split('.').nth(2).unwrap();
        let sig3 = jwt3.split('.').nth(2).unwrap();

        assert_ne!(
            sig1, sig2,
            "Signatures with different keys should be different"
        );
        assert_ne!(
            sig2, sig3,
            "Signatures with different keys should be different"
        );
        assert_ne!(
            sig1, sig3,
            "Signatures with different keys should be different"
        );
    }
}
