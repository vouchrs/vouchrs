// Integration test for Apple JWT functions using the refactored crypto module
use std::fs;
use std::path::Path;
use vouchrs::settings::JwtSigningConfig;
use vouchrs::utils::apple::generate_jwt_client_secret;
use vouchrs::utils::crypto::decode_jwt_payload;

// Helper function to create a test JWT signing config
fn create_test_jwt_config() -> JwtSigningConfig {
    create_test_jwt_config_with_path("/tmp/test_apple_key.p8")
}

// Helper function to create a test JWT signing config with custom path
fn create_test_jwt_config_with_path(path: &str) -> JwtSigningConfig {
    // Create a temporary test key file
    let test_key = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgpQUGzV2mpXNdjHnV
9QFCar9R+eojTjLOXCisVV9xfvehRANCAATyHpTDz7xyWXHaC0FXYlwK5r4IpeHx
1X4WXDZiAKUxHblBs1Kn15IR334KNiNP7gEWM+9BFuWh9uJwHGOBJXc/
-----END PRIVATE KEY-----"#;

    fs::write(path, test_key).expect("Failed to write test key file");

    JwtSigningConfig {
        team_id: Some("TEST123456".to_string()),
        key_id: Some("TEST789XYZ".to_string()),
        private_key_path: Some(path.to_string()),
        team_id_env: None,
        key_id_env: None,
        private_key_path_env: None,
    }
}

#[test]
fn test_apple_jwt_creation_with_crypto_module() {
    let jwt_config = create_test_jwt_config();
    let client_id = "com.example.testapp";

    // Generate Apple JWT using the refactored function
    let result = generate_jwt_client_secret(&jwt_config, client_id);
    
    match &result {
        Ok(_) => println!("✅ Apple JWT generation succeeded"),
        Err(e) => println!("❌ Apple JWT generation failed: {}", e),
    }
    
    assert!(result.is_ok(), "Apple JWT generation should succeed: {:?}", result.as_ref().err());
    let jwt = result.unwrap();
    
    // Verify JWT format (should have 3 parts separated by dots)
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT should have header.payload.signature format");
    
    // Decode and verify header
    let header_result = decode_jwt_payload(&format!("{}.{}.dummy", parts[0], parts[1]));
    assert!(header_result.is_ok(), "Should be able to decode JWT payload");
    
    let payload = header_result.unwrap();
    
    // Verify Apple-specific claims
    assert_eq!(payload["iss"], "TEST123456", "Issuer should be team ID");
    assert_eq!(payload["sub"], client_id, "Subject should be client ID");
    assert_eq!(payload["aud"], "https://appleid.apple.com", "Audience should be Apple ID");
    
    // Verify timestamps are present and reasonable
    assert!(payload["iat"].is_number(), "Issued at timestamp should be present");
    assert!(payload["exp"].is_number(), "Expiration timestamp should be present");
    
    let iat = payload["iat"].as_i64().unwrap();
    let exp = payload["exp"].as_i64().unwrap();
    
    // Token should expire 5 minutes (300 seconds) from issue time
    assert_eq!(exp - iat, 300, "Token should expire in 5 minutes");
    
    // Verify signature is present and not empty
    assert!(!parts[2].is_empty(), "Signature should not be empty");
    
    // Clean up test file
    if Path::new("/tmp/test_apple_key.p8").exists() {
        fs::remove_file("/tmp/test_apple_key.p8").unwrap();
    }
    
    println!("✅ Apple JWT integration test passed");
    println!("Generated JWT: {}", jwt);
}

#[test]
fn test_apple_jwt_missing_config() {
    let incomplete_config = JwtSigningConfig {
        team_id: None, // Missing team ID
        key_id: Some("TEST789XYZ".to_string()),
        private_key_path: Some("/tmp/nonexistent.p8".to_string()),
        team_id_env: None,
        key_id_env: None,
        private_key_path_env: None,
    };
    
    let result = generate_jwt_client_secret(&incomplete_config, "com.example.test");
    
    assert!(result.is_err(), "Should fail with missing team ID");
    assert!(result.unwrap_err().contains("Team ID not configured"));
}

#[test]
fn test_apple_jwt_invalid_key_file() {
    let invalid_config = JwtSigningConfig {
        team_id: Some("TEST123456".to_string()),
        key_id: Some("TEST789XYZ".to_string()),
        private_key_path: Some("/tmp/nonexistent_key.p8".to_string()),
        team_id_env: None,
        key_id_env: None,
        private_key_path_env: None,
    };
    
    let result = generate_jwt_client_secret(&invalid_config, "com.example.test");
    
    assert!(result.is_err(), "Should fail with missing key file");
    assert!(result.unwrap_err().contains("Failed to read Apple private key file"));
}

#[test]
fn test_apple_jwt_deterministic_with_same_input() {
    let test_key_path = "/tmp/test_apple_key_deterministic.p8";
    let jwt_config = create_test_jwt_config_with_path(test_key_path);
    let client_id = "com.example.testapp";

    // Generate two JWTs with the same parameters
    let jwt1 = generate_jwt_client_secret(&jwt_config, client_id).unwrap();
    
    // Wait a moment to ensure different timestamps
    std::thread::sleep(std::time::Duration::from_millis(1001));
    
    let jwt2 = generate_jwt_client_secret(&jwt_config, client_id).unwrap();
    
    // JWTs should be different due to different timestamps
    assert_ne!(jwt1, jwt2, "JWTs should differ due to different timestamps");
    
    // But they should have the same structure
    let parts1: Vec<&str> = jwt1.split('.').collect();
    let parts2: Vec<&str> = jwt2.split('.').collect();
    
    // Headers should be identical (same algorithm and key ID)
    assert_eq!(parts1[0], parts2[0], "Headers should be identical");
    
    // Payloads should differ only in timestamps
    let payload1 = decode_jwt_payload(&format!("{}.{}.dummy", parts1[0], parts1[1])).unwrap();
    let payload2 = decode_jwt_payload(&format!("{}.{}.dummy", parts2[0], parts2[1])).unwrap();
    
    assert_eq!(payload1["iss"], payload2["iss"], "Issuers should match");
    assert_eq!(payload1["sub"], payload2["sub"], "Subjects should match");
    assert_eq!(payload1["aud"], payload2["aud"], "Audiences should match");
    
    // Timestamps should be different
    assert_ne!(payload1["iat"], payload2["iat"], "Issue times should differ");
    assert_ne!(payload1["exp"], payload2["exp"], "Expiry times should differ");
    
    // Clean up test file
    if Path::new(test_key_path).exists() {
        fs::remove_file(test_key_path).unwrap();
    }
    
    println!("✅ Apple JWT deterministic test passed");
}
