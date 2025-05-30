// Integration test for JWT settings and OAuth callback functionality
use vouchrs::settings::VouchrsSettings;
use vouchrs::jwt_utils::{create_access_token, UserAgentInfo};
use vouchrs::utils::test_helpers::{create_test_session, create_test_settings};
use serde_json::Value;
use base64::{Engine as _, engine::general_purpose};

#[test]
fn test_jwt_settings_fallback_to_defaults() {
    // Test that JWT settings fall back to defaults when not configured
    let default_settings = VouchrsSettings::default();
    
    assert_eq!(default_settings.jwt.issuer, "https://vouchrs.app");
    assert_eq!(default_settings.jwt.audience, "https://api.example.com");
    assert_eq!(default_settings.jwt.session_duration_hours, 24);
    assert_eq!(default_settings.jwt.session_secret, "your-jwt-secret-key-here-must-be-at-least-32-chars-long-for-aes256");
}

#[test]
fn test_jwt_env_override_priority() {
    // Test that environment variables override default values
    std::env::set_var("JWT_ISSUER", "https://custom-issuer.example.com");
    std::env::set_var("JWT_AUDIENCE", "https://custom-audience.example.com");
    
    let mut settings = VouchrsSettings::default();
    VouchrsSettings::apply_jwt_env_overrides(&mut settings.jwt);
    
    assert_eq!(settings.jwt.issuer, "https://custom-issuer.example.com");
    assert_eq!(settings.jwt.audience, "https://custom-audience.example.com");
    
    // Clean up
    std::env::remove_var("JWT_ISSUER");
    std::env::remove_var("JWT_AUDIENCE");
}

#[test]
fn test_access_token_contains_required_fields() {
    // Create a session with proper provider_id set
    let mut session = create_test_session();
    session.provider_id = "test_provider_id_123".to_string();
    session.provider = "google".to_string();
    
    let settings = create_test_settings();
    
    // Create user agent info with platform
    let user_agent_info = UserAgentInfo {
        user_agent: Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36".to_string()),
        platform: Some("macOS".to_string()),
        lang: Some("en-US".to_string()),
        mobile: 0,
    };
    
    // Create access token
    let token = create_access_token(&session, &settings, Some("192.168.1.1"), Some(&user_agent_info))
        .expect("Should create access token");
    
    // Parse the JWT to verify contents
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT should have 3 parts");
    
    let payload_b64 = parts[1];
    let payload_bytes = general_purpose::URL_SAFE_NO_PAD.decode(payload_b64).unwrap();
    let payload: Value = serde_json::from_slice(&payload_bytes).unwrap();
    
    // Verify required JWT claims are present and correct
    assert_eq!(payload["iss"].as_str().unwrap(), settings.jwt.issuer, "Issuer should match settings");
    assert_eq!(payload["aud"].as_str().unwrap(), settings.jwt.audience, "Audience should match settings");
    assert_eq!(payload["sub"].as_str().unwrap(), session.user_email, "Subject should match user email");
    assert_eq!(payload["idp"].as_str().unwrap(), session.provider, "Identity provider should be set");
    assert_eq!(payload["idp_id"].as_str().unwrap(), session.provider_id, "Provider ID should be set");
    if let Some(ref name) = session.user_name {
        assert_eq!(payload["name"].as_str().unwrap(), name, "Name should be set");
    }
    assert_eq!(payload["platform"].as_str().unwrap(), "macOS", "Platform should be extracted from user agent");
    assert_eq!(payload["client_ip"].as_str().unwrap(), "192.168.1.1", "Client IP should be set");
    assert_eq!(payload["lang"].as_str().unwrap(), "en-US", "Language should be set");
    assert_eq!(payload["mobile"].as_u64().unwrap(), 0, "Mobile flag should be set");
    
    // Verify timestamps are reasonable
    assert!(payload["iat"].is_number(), "Issued at should be a number");
    assert!(payload["exp"].is_number(), "Expires at should be a number");
    
    println!("✅ All JWT claims verified successfully");
}

#[test]
fn test_minimal_jwt_token() {
    // Test creating a JWT with minimal information
    let mut session = create_test_session();
    session.provider_id = "minimal_provider_id".to_string();
    
    let settings = create_test_settings();
    
    // Create access token without user agent info or client IP
    let token = create_access_token(&session, &settings, None, None)
        .expect("Should create access token");
    
    // Parse the JWT to verify contents
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT should have 3 parts");
    
    let payload_b64 = parts[1];
    let payload_bytes = general_purpose::URL_SAFE_NO_PAD.decode(payload_b64).unwrap();
    let payload: Value = serde_json::from_slice(&payload_bytes).unwrap();
    
    // Verify required claims are still present
    assert_eq!(payload["iss"].as_str().unwrap(), settings.jwt.issuer);
    assert_eq!(payload["aud"].as_str().unwrap(), settings.jwt.audience);
    assert_eq!(payload["idp_id"].as_str().unwrap(), "minimal_provider_id");
    
    // Verify optional fields are not present when not provided
    assert!(payload.get("client_ip").is_none(), "Client IP should not be present");
    assert!(payload.get("user_agent").is_none(), "User agent should not be present");
    assert!(payload.get("platform").is_none(), "Platform should not be present");
    assert!(payload.get("lang").is_none(), "Language should not be present");
    
    println!("✅ Minimal JWT token verified successfully");
}
