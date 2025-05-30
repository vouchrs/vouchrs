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

/// Create an access token (JWT) from session data and settings
pub fn create_access_token(
    session: &crate::models::VouchrsSession,
    settings: &crate::settings::VouchrsSettings,
    client_ip: Option<&str>,
    user_agent_info: Option<&UserAgentInfo>,
) -> Result<String> {
    // Create the JWT payload with the required structure
    let mut payload = json!({
        "iss": settings.jwt.issuer,
        "aud": settings.jwt.audience,
        "exp": session.expires_at.timestamp(),
        "iat": session.created_at.timestamp(),
        "sub": session.user_email,
        "idp": session.provider,
        "idp_id": session.provider_id,
        "name": session.user_name
    });
    
    // Add client IP if available
    if let Some(ip) = client_ip {
        payload["client_ip"] = json!(ip);
    }
    
    // Add user agent information if available
    if let Some(ua_info) = user_agent_info {
        if let Some(ref user_agent) = ua_info.user_agent {
            payload["user_agent"] = json!(user_agent);
        }
        if let Some(ref platform) = ua_info.platform {
            payload["platform"] = json!(platform);
        }
        if let Some(ref lang) = ua_info.lang {
            payload["lang"] = json!(lang);
        }
        payload["mobile"] = json!(ua_info.mobile);
    }
    
    // Sign the JWT with the session secret
    create_jwt(payload, &settings.jwt.session_secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_helpers::{create_test_session, create_test_settings};
    
    #[test]
    fn test_create_access_token() {
        let session = create_test_session();
        let settings = create_test_settings();
        
        let jwt = create_access_token(&session, &settings, Some("203.0.113.42"), None).unwrap();
        
        // JWT should have 3 parts separated by dots
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        
        // Decode and verify the payload
        let payload_b64 = parts[1];
        let payload_bytes = general_purpose::URL_SAFE_NO_PAD.decode(payload_b64).unwrap();
        let payload: Value = serde_json::from_slice(&payload_bytes).unwrap();
        
        assert_eq!(payload["iss"], "https://vouchrs.app");
        assert_eq!(payload["aud"], "http://localhost:3000");
        assert_eq!(payload["sub"], "test@example.com");
        assert_eq!(payload["idp"], "google");
        assert_eq!(payload["idp_id"], "123456789");
        assert_eq!(payload["name"], "Test User");
        assert_eq!(payload["client_ip"], "203.0.113.42");
    }
    
    #[test]
    fn test_create_access_token_without_client_ip() {
        let session = create_test_session();
        let settings = create_test_settings();
        
        let jwt = create_access_token(&session, &settings, None, None).unwrap();
        
        // JWT should have 3 parts separated by dots
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        
        // Decode and verify the payload
        let payload_b64 = parts[1];
        let payload_bytes = general_purpose::URL_SAFE_NO_PAD.decode(payload_b64).unwrap();
        let payload: Value = serde_json::from_slice(&payload_bytes).unwrap();
        
        // Verify standard claims are present
        assert_eq!(payload["iss"], "https://vouchrs.app");
        assert_eq!(payload["sub"], "test@example.com");
        assert_eq!(payload["idp"], "google");
        
        // Verify client_ip claim is not present when None is passed
        assert!(payload.get("client_ip").is_none(), "client_ip should not be present when None is passed");
    }
    
    #[test]
    fn test_create_access_token_with_user_agent_info() {
        let session = create_test_session();
        let settings = create_test_settings();
        
        let user_agent_info = UserAgentInfo {
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string()),
            platform: Some("Windows".to_string()),
            lang: Some("en-US".to_string()),
            mobile: 0,
        };
        
        let jwt = create_access_token(&session, &settings, Some("203.0.113.42"), Some(&user_agent_info)).unwrap();
        
        // JWT should have 3 parts separated by dots
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        
        // Decode and verify the payload
        let payload_b64 = parts[1];
        let payload_bytes = general_purpose::URL_SAFE_NO_PAD.decode(payload_b64).unwrap();
        let payload: Value = serde_json::from_slice(&payload_bytes).unwrap();
        
        // Verify standard claims
        assert_eq!(payload["sub"], "test@example.com");
        assert_eq!(payload["client_ip"], "203.0.113.42");
        
        // Verify user agent claims
        assert_eq!(payload["user_agent"], "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
        assert_eq!(payload["platform"], "Windows");
        assert_eq!(payload["lang"], "en-US");
        assert_eq!(payload["mobile"], 0);
    }
}
