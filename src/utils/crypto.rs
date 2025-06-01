// Cryptographic utilities for generating secure tokens and nonces

use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;

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
}
