// Tests for JWT handlers - now focused on SessionBuilder functionality
use crate::models::{AppleUserInfo, AppleUserName};
use crate::handlers::session_builder::SessionBuilder;
use chrono::Utc;

#[test]
fn test_session_builder_with_apple_user_info_fallback() {
    // Test SessionBuilder using Apple user info when ID token lacks name
    let apple_user_info = AppleUserInfo {
        name: AppleUserName {
            first_name: Some("John".to_string()),
            last_name: Some("Doe".to_string()),
        },
        email: Some("john.doe@example.com".to_string()),
    };
    let id_token = Some("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZW1haWwiOiJmYWxsYmFja0BleGFtcGxlLmNvbSJ9.invalid".to_string());
    let refresh_token = None;
    let expires_at = Utc::now();
    let result = SessionBuilder::build_session_with_apple_info(
        "apple".to_string(),
        id_token,
        refresh_token,
        expires_at,
        Some(apple_user_info),
    );
    
    assert!(result.is_ok());
    let session = result.unwrap();
    assert_eq!(session.user_email, "fallback@example.com"); // From ID token
    assert_eq!(session.user_name, Some("John Doe".to_string())); // From Apple user info fallback
    assert_eq!(session.provider_id, "1234567890");
}

#[test]
fn test_session_builder_with_google_tokens() {
    // Test SessionBuilder with Google-style ID tokens (name in 'name' field)
    let id_token = Some("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZW1haWwiOiJnb29nbGVAZXhhbXBsZS5jb20iLCJuYW1lIjoiR29vZ2xlIFVzZXIifQ.invalid".to_string());
    let refresh_token = None;
    let expires_at = Utc::now();
    let result = SessionBuilder::build_session(
        "google".to_string(),
        id_token,
        refresh_token,
        expires_at,
    );
    
    assert!(result.is_ok());
    let session = result.unwrap();
    assert_eq!(session.user_email, "google@example.com");
    assert_eq!(session.user_name, Some("Google User".to_string()));
    assert_eq!(session.provider_id, "1234567890");
}

#[test]
fn test_session_builder_with_invalid_token() {
    // Test SessionBuilder with actually invalid JWT token
    let id_token = Some("completely.invalid.token".to_string());
    let refresh_token = None;
    let expires_at = Utc::now();
    let result = SessionBuilder::build_session(
        "test".to_string(),
        id_token,
        refresh_token,
        expires_at,
    );
    
    // This should fail because the token format is invalid
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Base64 decode failed"));
}

#[test]
fn test_session_builder_without_id_token() {
    // Test SessionBuilder when no ID token is provided
    let id_token = None;
    let refresh_token = None;
    let expires_at = Utc::now();
    let result = SessionBuilder::build_session(
        "test".to_string(),
        id_token,
        refresh_token,
        expires_at,
    );
    
    // This should fail because no ID token is available
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("No ID token available"));
}
