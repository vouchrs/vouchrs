// JWT utilities for creating and signing JWTs
use anyhow::Result;
use base64::{Engine as _, engine::general_purpose};
use serde_json::{json, Value};

/// User agent information extracted from HTTP headers
#[derive(Debug, Clone)]
pub struct UserAgentInfo {
    pub user_agent: Option<String>,
    pub platform: Option<String>,
    pub lang: Option<String>,
    pub mobile: u8, // 0 or 1
}

/// HMAC-SHA256 implementation for JWT signing
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    // Use the hmac-sha256 crate for proper HMAC-SHA256 implementation
    let mac = hmac_sha256::HMAC::mac(data, key);
    mac.to_vec()
}

/// Create a JWT token with the given payload and sign it with the provided secret
pub fn create_jwt(payload: Value, secret: &str) -> Result<String> {
    // Create JWT header
    let header = json!({
        "alg": "HS256",
        "typ": "JWT"
    });
    
    // Encode header and payload to base64
    let header_json = serde_json::to_string(&header)?;
    let payload_json = serde_json::to_string(&payload)?;
    
    let header_b64 = general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    let payload_b64 = general_purpose::URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    
    // Create the message to sign
    let message = format!("{}.{}", header_b64, payload_b64);
    
    // Sign with HMAC-SHA256
    let signature = hmac_sha256(secret.as_bytes(), message.as_bytes());
    let signature_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&signature);
    
    // Combine all parts
    let jwt = format!("{}.{}", message, signature_b64);
    
    Ok(jwt)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hmac_sha256_basic() {
        let key = b"secret";
        let data = b"message";
        let result = hmac_sha256(key, data);
        
        // HMAC-SHA256 should always produce 32 bytes
        assert_eq!(result.len(), 32);
    }
    
    #[test]
    fn test_create_jwt_basic() {
        let payload = json!({
            "sub": "test@example.com",
            "exp": 1234567890
        });
        
        let jwt = create_jwt(payload, "secret").unwrap();
        
        // JWT should have 3 parts separated by dots
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        
        // Decode and verify the payload
        let payload_b64 = parts[1];
        let payload_bytes = general_purpose::URL_SAFE_NO_PAD.decode(payload_b64).unwrap();
        let decoded_payload: Value = serde_json::from_slice(&payload_bytes).unwrap();
        
        assert_eq!(decoded_payload["sub"], "test@example.com");
        assert_eq!(decoded_payload["exp"], 1234567890);
    }
}
