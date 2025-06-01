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
/// - Base64URL encoding results in 32 characters vs UUID's 36 characters
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
    rand::thread_rng().fill_bytes(&mut nonce);
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
    rand::thread_rng().fill_bytes(&mut nonce);
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
        return Err(anyhow!("Invalid key length: expected {} bytes, got {}", ENCRYPTION_KEY_SIZE, key.len()));
    }

    // Serialize the data to JSON
    let json_data = serde_json::to_string(data).context("Failed to serialize data")?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
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
        return Err(anyhow!("Invalid key length: expected {} bytes, got {}", ENCRYPTION_KEY_SIZE, key.len()));
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
pub fn derive_encryption_key(input_key: &[u8]) -> [u8; ENCRYPTION_KEY_SIZE] {
    let mut encryption_key = [0u8; ENCRYPTION_KEY_SIZE];
    let key_len = std::cmp::min(input_key.len(), ENCRYPTION_KEY_SIZE);
    encryption_key[..key_len].copy_from_slice(&input_key[..key_len]);

    // If key is shorter than 32 bytes, derive the rest using a simple hash
    if key_len < ENCRYPTION_KEY_SIZE {
        for i in key_len..ENCRYPTION_KEY_SIZE {
            encryption_key[i] = encryption_key[i % key_len].wrapping_add(u8::try_from(i % 256).unwrap_or(0));
        }
    }

    encryption_key
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_csrf_token_generation() {
        let token = generate_csrf_token();
        
        // Should be 32 characters (24 bytes base64url encoded)
        assert_eq!(token.len(), 32);
        
        // Should only contain base64url characters
        assert!(token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        
        // Should not contain padding
        assert!(!token.contains('='));
    }

    #[test]
    fn test_csrf_token_uniqueness() {
        let mut tokens = HashSet::new();
        
        // Generate 1000 tokens and ensure they're all unique
        for _ in 0..1000 {
            let token = generate_csrf_token();
            assert!(tokens.insert(token), "Generated duplicate CSRF token");
        }
    }

    #[test]
    fn test_nonce_generation_various_lengths() {
        // Test different nonce lengths
        for length in [8, 16, 24, 32] {
            let nonce = generate_nonce(length);
            
            // Base64url encoding: 4 chars per 3 bytes, rounded up
            let expected_len = (length * 4 + 2) / 3;
            assert_eq!(nonce.len(), expected_len);
            
            // Should only contain base64url characters
            assert!(nonce.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        }
    }

    #[test]
    fn test_nonce_entropy() {
        // Generate multiple nonces and ensure they're different
        let nonce1 = generate_nonce(32);
        let nonce2 = generate_nonce(32);
        let nonce3 = generate_nonce(32);
        
        assert_ne!(nonce1, nonce2);
        assert_ne!(nonce2, nonce3);
        assert_ne!(nonce1, nonce3);
    }

    #[test]
    fn test_csrf_token_optimal_length() {
        let csrf_token = generate_csrf_token();
        
        // Verify optimal length for URLs (shorter than typical UUID at 36 chars)
        assert_eq!(csrf_token.len(), 32);  // 24 bytes base64url encoded
        
        // Verify it's shorter than traditional UUID format
        assert!(csrf_token.len() < 36);  // UUID format with hyphens is 36 chars
        
        // Verify it has good entropy density (24 bytes = 192 bits)
        // This provides much better entropy-to-length ratio than UUID v4 (122 bits in 36 chars)
        let entropy_bits = 192;
        let entropy_per_char = entropy_bits as f64 / csrf_token.len() as f64;
        assert!(entropy_per_char > 5.0);  // Should be 6.0 bits per character
    }

    #[test]
    fn test_decode_jwt_payload() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let payload = decode_jwt_payload(token).expect("Failed to decode JWT payload");

        // Ensure the payload contains expected fields
        assert_eq!(payload["sub"], "1234567890");
        assert_eq!(payload["name"], "John Doe");
        assert_eq!(payload["iat"], 1516239022);
    }

    #[test]
    fn test_decode_jwt_payload_invalid_format() {
        let token = "invalid.jwt"; // Only 2 parts, not 3
        let result = decode_jwt_payload(token);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), "Invalid JWT format");
    }

    #[test]
    fn test_decode_jwt_payload_base64_decode_fail() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid!!base64!!.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let result = decode_jwt_payload(token);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), "Base64 decode failed");
    }

    #[test]
    fn test_decode_jwt_payload_utf8_decode_fail() {
        // Create a payload with invalid UTF-8 bytes
        let invalid_utf8_bytes = vec![0xff, 0xfe, 0xfd, 0xfc]; // Invalid UTF-8 sequence
        let invalid_payload = general_purpose::URL_SAFE_NO_PAD.encode(&invalid_utf8_bytes);
        let token = format!("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", invalid_payload);
        let result = decode_jwt_payload(&token);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), "UTF-8 decode failed");
    }

    #[test]
    fn test_decode_jwt_payload_json_parse_fail() {
        // Create a payload that's valid UTF-8 but invalid JSON
        let invalid_json = "not valid json at all";
        let invalid_payload = general_purpose::URL_SAFE_NO_PAD.encode(invalid_json.as_bytes());
        let token = format!("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", invalid_payload);
        let result = decode_jwt_payload(&token);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), "JSON parse failed");
    }

    #[test]
    fn test_encryption_decryption_round_trip() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct TestData {
            name: String,
            age: u32,
            active: bool,
        }

        let test_data = TestData {
            name: "John Doe".to_string(),
            age: 30,
            active: true,
        };

        let key = derive_encryption_key(b"test_key_32_bytes_long_for_testing");
        
        // Encrypt the data
        let encrypted = encrypt_data(&test_data, &key).expect("Encryption should succeed");
        assert!(!encrypted.is_empty());
        
        // Decrypt the data
        let decrypted: TestData = decrypt_data(&encrypted, &key).expect("Decryption should succeed");
        assert_eq!(test_data, decrypted);
    }

    #[test]
    fn test_encryption_with_invalid_key_length() {
        let test_data = "test data";
        let short_key = b"short";
        
        let result = encrypt_data(&test_data, short_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid key length"));
    }

    #[test]
    fn test_decryption_with_invalid_key_length() {
        let encrypted_data = "fake_encrypted_data";
        let short_key = b"short";
        
        let result: Result<String> = decrypt_data(encrypted_data, short_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid key length"));
    }

    #[test]
    fn test_derive_encryption_key() {
        // Test with key shorter than 32 bytes
        let short_key = b"test_key";
        let derived = derive_encryption_key(short_key);
        assert_eq!(derived.len(), ENCRYPTION_KEY_SIZE);
        assert_eq!(&derived[..short_key.len()], short_key);
        
        // Test with key exactly 32 bytes
        let exact_key = b"this_is_exactly_32_bytes_long___";
        let derived = derive_encryption_key(exact_key);
        assert_eq!(derived.len(), ENCRYPTION_KEY_SIZE);
        assert_eq!(&derived[..], exact_key);
        
        // Test with key longer than 32 bytes
        let long_key = b"this_is_a_very_long_key_that_is_longer_than_32_bytes";
        let derived = derive_encryption_key(long_key);
        assert_eq!(derived.len(), ENCRYPTION_KEY_SIZE);
        assert_eq!(&derived[..], &long_key[..ENCRYPTION_KEY_SIZE]);
    }

    #[test]
    fn test_encryption_produces_different_outputs() {
        let test_data = "same data";
        let key = derive_encryption_key(b"test_key_32_bytes_long_for_testing");
        
        // Encrypt the same data multiple times
        let encrypted1 = encrypt_data(&test_data, &key).expect("Encryption should succeed");
        let encrypted2 = encrypt_data(&test_data, &key).expect("Encryption should succeed");
        
        // Due to random nonces, encrypted outputs should be different
        assert_ne!(encrypted1, encrypted2);
        
        // But both should decrypt to the same original data
        let decrypted1: String = decrypt_data(&encrypted1, &key).expect("Decryption should succeed");
        let decrypted2: String = decrypt_data(&encrypted2, &key).expect("Decryption should succeed");
        assert_eq!(decrypted1, test_data);
        assert_eq!(decrypted2, test_data);
    }

}
