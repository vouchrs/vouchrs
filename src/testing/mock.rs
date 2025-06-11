//! Mock objects and fake implementations for testing
//!
//! This module provides mock implementations of external dependencies
//! and services for isolated unit testing.

use crate::oauth::{OAuthCallback, OAuthState};
use crate::settings::JwtSigningConfig;
use crate::utils::headers::UserAgentInfo;
use serde_json::Value;
use std::collections::HashMap;

/// Mock OAuth callback data for testing OAuth flows
pub struct MockOAuthCallback;

impl MockOAuthCallback {
    /// Create a successful OAuth callback
    #[must_use]
    pub fn success(code: &str, state: &str) -> OAuthCallback {
        OAuthCallback {
            code: Some(code.to_string()),
            state: Some(state.to_string()),
            error: None,
            user: None,
        }
    }

    /// Create an OAuth callback with error
    pub fn error(error: &str, state: Option<&str>) -> OAuthCallback {
        OAuthCallback {
            code: None,
            state: state.map(ToString::to_string),
            error: Some(error.to_string()),
            user: None,
        }
    }

    /// Create OAuth callback with Apple user data
    ///
    /// # Panics
    ///
    /// Panics if the `user_json` is not valid JSON.
    #[must_use]
    pub fn apple_with_user(code: &str, state: &str, user_json: &str) -> OAuthCallback {
        OAuthCallback {
            code: Some(code.to_string()),
            state: Some(state.to_string()),
            error: None,
            user: Some(serde_json::from_str(user_json).unwrap()),
        }
    }

    /// Create OAuth callback missing required fields
    #[must_use]
    pub fn incomplete() -> OAuthCallback {
        OAuthCallback {
            code: None,
            state: None,
            error: None,
            user: None,
        }
    }
}

/// Mock OAuth state data for testing
pub struct MockOAuthState;

impl MockOAuthState {
    /// Create a standard OAuth state
    #[must_use]
    pub fn standard(provider: &str) -> OAuthState {
        OAuthState {
            state: format!("csrf_token_{provider}"),
            provider: provider.to_string(),
            redirect_url: Some("/dashboard".to_string()),
        }
    }

    /// Create OAuth state without redirect
    #[must_use]
    pub fn no_redirect(provider: &str) -> OAuthState {
        OAuthState {
            state: format!("csrf_token_{provider}"),
            provider: provider.to_string(),
            redirect_url: None,
        }
    }

    /// Create OAuth state with custom redirect
    #[must_use]
    pub fn with_redirect(provider: &str, redirect: &str) -> OAuthState {
        OAuthState {
            state: format!("csrf_token_{provider}"),
            provider: provider.to_string(),
            redirect_url: Some(redirect.to_string()),
        }
    }
}

/// Mock JWT signing configuration for testing Apple JWT
pub struct MockJwtConfig;

impl MockJwtConfig {
    /// Create a valid test JWT config
    #[must_use]
    pub fn valid() -> JwtSigningConfig {
        JwtSigningConfig {
            team_id: Some("TEST123456".to_string()),
            key_id: Some("TEST789XYZ".to_string()),
            private_key_path: Some("/tmp/test_apple_key.p8".to_string()),
            team_id_env: None,
            key_id_env: None,
            private_key_path_env: None,
        }
    }

    /// Create JWT config with missing team ID
    #[must_use]
    pub fn missing_team_id() -> JwtSigningConfig {
        JwtSigningConfig {
            team_id: None,
            key_id: Some("TEST789XYZ".to_string()),
            private_key_path: Some("/tmp/test_apple_key.p8".to_string()),
            team_id_env: None,
            key_id_env: None,
            private_key_path_env: None,
        }
    }

    /// Create JWT config with invalid key path
    #[must_use]
    pub fn invalid_key_path() -> JwtSigningConfig {
        JwtSigningConfig {
            team_id: Some("TEST123456".to_string()),
            key_id: Some("TEST789XYZ".to_string()),
            private_key_path: Some("/nonexistent/path.p8".to_string()),
            team_id_env: None,
            key_id_env: None,
            private_key_path_env: None,
        }
    }

    /// Create and write a temporary test key file
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be created or written to.
    pub fn create_test_key_file(path: &str) -> std::io::Result<()> {
        let test_key = Self::generate_test_private_key();
        std::fs::write(path, test_key)
    }

    /// Generate a new P-256 private key for testing
    ///
    /// This creates a fresh cryptographic key each time it's called,
    /// eliminating the security risk of hardcoded keys in source code.
    ///
    /// # Returns
    ///
    /// A PEM-formatted P-256 private key suitable for ES256 JWT signing
    ///
    /// # Panics
    ///
    /// Panics if the cryptographic key generation or PEM encoding fails.
    /// This should only happen in exceptional circumstances like
    /// insufficient system entropy or memory allocation failures.
    #[must_use]
    pub fn generate_test_private_key() -> String {
        use p256::pkcs8::EncodePrivateKey;
        use p256::SecretKey;

        // Generate a new random P-256 secret key
        let secret_key = SecretKey::random(&mut rand::rng());

        // Encode as PKCS#8 PEM format
        secret_key
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .expect("Failed to encode private key as PKCS#8 PEM")
            .to_string()
    }

    /// Clean up test key file
    pub fn cleanup_test_key_file(path: &str) {
        if std::path::Path::new(path).exists() {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Mock passkey registration data
pub struct MockPasskeyData;

impl MockPasskeyData {
    /// Create valid passkey registration data
    #[must_use]
    pub fn valid_registration() -> Value {
        serde_json::json!({
            "rawId": "dGVzdF9jcmVkZW50aWFsX2lk", // base64: "test_credential_id"
            "response": {
                "attestationObject": "dGVzdF9hdHRlc3RhdGlvbg==", // base64: "test_attestation"
                "clientDataJSON": "dGVzdF9jbGllbnRfZGF0YQ==" // base64: "test_client_data"
            },
            "type": "public-key"
        })
    }

    /// Create invalid passkey registration data (invalid base64)
    #[must_use]
    pub fn invalid_registration() -> Value {
        serde_json::json!({
            "rawId": "invalid_base64!@#",
            "response": {
                "attestationObject": "",
                "clientDataJSON": ""
            }
        })
    }

    /// Create passkey registration data with missing fields
    #[must_use]
    pub fn incomplete_registration() -> Value {
        serde_json::json!({
            "rawId": "dGVzdF9jcmVkZW50aWFsX2lk"
            // Missing response field
        })
    }

    /// Create valid passkey authentication data
    #[must_use]
    pub fn valid_authentication() -> Value {
        serde_json::json!({
            "rawId": "dGVzdF9jcmVkZW50aWFsX2lk", // base64: "test_credential_id"
            "response": {
                "authenticatorData": "dGVzdF9hdXRoX2RhdGE=", // base64: "test_auth_data"
                "clientDataJSON": "dGVzdF9jbGllbnRfZGF0YQ==", // base64: "test_client_data"
                "signature": "dGVzdF9zaWduYXR1cmU=" // base64: "test_signature"
            },
            "type": "public-key"
        })
    }

    /// Create passkey authentication data with null values
    #[must_use]
    pub fn null_authentication() -> Value {
        serde_json::json!({
            "rawId": null,
            "response": {
                "authenticatorData": "test",
                "clientDataJSON": "test",
                "signature": "test"
            }
        })
    }
}

/// Mock user agent data for different platforms
pub struct MockUserAgent;

impl MockUserAgent {
    /// Desktop Chrome on Windows
    #[must_use]
    pub fn windows_chrome() -> UserAgentInfo {
        UserAgentInfo {
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36".to_string()),
            platform: Some("Windows".to_string()),
            lang: Some("en-US".to_string()),
            mobile: 0,
        }
    }

    /// Desktop Safari on macOS
    #[must_use]
    pub fn macos_safari() -> UserAgentInfo {
        UserAgentInfo {
            user_agent: Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15".to_string()),
            platform: Some("macOS".to_string()),
            lang: Some("en-US".to_string()),
            mobile: 0,
        }
    }

    /// Mobile Safari on iPhone
    #[must_use]
    pub fn iphone_safari() -> UserAgentInfo {
        UserAgentInfo {
            user_agent: Some("Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1".to_string()),
            platform: Some("iOS".to_string()),
            lang: Some("en-US".to_string()),
            mobile: 1,
        }
    }

    /// Mobile Chrome on Android
    #[must_use]
    pub fn android_chrome() -> UserAgentInfo {
        UserAgentInfo {
            user_agent: Some("Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36".to_string()),
            platform: Some("Android".to_string()),
            lang: Some("en-US".to_string()),
            mobile: 1,
        }
    }

    /// API client (non-browser)
    #[must_use]
    pub fn api_client() -> UserAgentInfo {
        UserAgentInfo {
            user_agent: Some("TestApp/1.0".to_string()),
            platform: None,
            lang: None,
            mobile: 0,
        }
    }

    /// User agent with different language
    #[must_use]
    pub fn french_browser() -> UserAgentInfo {
        UserAgentInfo {
            user_agent: Some(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36".to_string(),
            ),
            platform: Some("macOS".to_string()),
            lang: Some("fr-FR".to_string()),
            mobile: 0,
        }
    }
}

/// Mock validation data for testing edge cases
pub struct MockValidationData;

impl MockValidationData {
    /// Create data with extremely long fields
    #[must_use]
    pub fn oversized_data() -> HashMap<String, String> {
        let mut data = HashMap::new();
        data.insert("name".to_string(), "a".repeat(1000)); // Very long name
        data.insert(
            "email".to_string(),
            format!("{}@example.com", "a".repeat(250)),
        ); // Very long email
        data.insert(
            "redirect_url".to_string(),
            format!("https://example.com/{}", "a".repeat(2000)),
        ); // Very long URL
        data
    }

    /// Create data with special characters
    #[must_use]
    pub fn special_characters_data() -> HashMap<String, String> {
        let mut data = HashMap::new();
        data.insert(
            "name".to_string(),
            "test<script>alert('xss')</script>".to_string(),
        );
        data.insert("email".to_string(), "test@@example.com".to_string());
        data.insert(
            "redirect_url".to_string(),
            "javascript:alert('xss')".to_string(),
        );
        data
    }

    /// Create data with unicode characters
    #[must_use]
    pub fn unicode_data() -> HashMap<String, String> {
        let mut data = HashMap::new();
        data.insert("name".to_string(), "测试用户名 🚀".to_string());
        data.insert("email".to_string(), "тест@example.com".to_string());
        data.insert("platform".to_string(), "🖥️ Desktop".to_string());
        data
    }

    /// Create empty/null data
    #[must_use]
    pub fn empty_data() -> HashMap<String, String> {
        let mut data = HashMap::new();
        data.insert("name".to_string(), String::new());
        data.insert("email".to_string(), String::new());
        data.insert("redirect_url".to_string(), String::new());
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_oauth_callback() {
        let success = MockOAuthCallback::success("auth_code_123", "state_456");
        assert_eq!(success.code, Some("auth_code_123".to_string()));
        assert_eq!(success.state, Some("state_456".to_string()));
        assert!(success.error.is_none());

        let error = MockOAuthCallback::error("access_denied", Some("state_456"));
        assert!(error.code.is_none());
        assert_eq!(error.error, Some("access_denied".to_string()));
    }

    #[test]
    fn test_mock_oauth_state() {
        let state = MockOAuthState::standard("google");
        assert_eq!(state.provider, "google");
        assert!(state.redirect_url.is_some());

        let no_redirect = MockOAuthState::no_redirect("github");
        assert_eq!(no_redirect.provider, "github");
        assert!(no_redirect.redirect_url.is_none());
    }

    #[test]
    fn test_mock_jwt_config() {
        let valid = MockJwtConfig::valid();
        assert!(valid.team_id.is_some());
        assert!(valid.key_id.is_some());

        let missing = MockJwtConfig::missing_team_id();
        assert!(missing.team_id.is_none());
        assert!(missing.key_id.is_some());
    }

    #[test]
    fn test_mock_passkey_data() {
        let valid = MockPasskeyData::valid_registration();
        assert!(valid.get("rawId").is_some());
        assert!(valid.get("response").is_some());

        let invalid = MockPasskeyData::invalid_registration();
        assert_eq!(
            invalid.get("rawId").unwrap().as_str().unwrap(),
            "invalid_base64!@#"
        );
    }

    #[test]
    fn test_mock_user_agents() {
        let windows = MockUserAgent::windows_chrome();
        assert_eq!(windows.mobile, 0);
        assert_eq!(windows.platform, Some("Windows".to_string()));

        let iphone = MockUserAgent::iphone_safari();
        assert_eq!(iphone.mobile, 1);
        assert_eq!(iphone.platform, Some("iOS".to_string()));
    }

    #[test]
    fn test_mock_validation_data() {
        let oversized = MockValidationData::oversized_data();
        assert!(oversized.get("name").unwrap().len() > 500);

        let special = MockValidationData::special_characters_data();
        assert!(special.get("name").unwrap().contains("<script>"));

        let empty = MockValidationData::empty_data();
        assert!(empty.get("name").unwrap().is_empty());
    }

    #[test]
    fn test_dynamic_key_generation() {
        // Generate multiple keys and verify they are different
        let key1 = MockJwtConfig::generate_test_private_key();
        let key2 = MockJwtConfig::generate_test_private_key();
        let key3 = MockJwtConfig::generate_test_private_key();

        // All keys should be valid PKCS#8 PEM format
        assert!(key1.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(key1.trim_end().ends_with("-----END PRIVATE KEY-----"));
        assert!(key2.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(key2.trim_end().ends_with("-----END PRIVATE KEY-----"));
        assert!(key3.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(key3.trim_end().ends_with("-----END PRIVATE KEY-----"));

        // Each key should be different (cryptographic randomness test)
        assert_ne!(key1, key2, "First and second keys should be different");
        assert_ne!(key2, key3, "Second and third keys should be different");
        assert_ne!(key1, key3, "First and third keys should be different");

        // Keys should be reasonably long (P-256 private keys in PEM format)
        assert!(key1.len() > 200, "Key should be substantial length");
        assert!(key2.len() > 200, "Key should be substantial length");
        assert!(key3.len() > 200, "Key should be substantial length");
    }

    #[test]
    fn test_create_test_key_file_with_dynamic_generation() {
        use tempfile::NamedTempFile;

        // Create a temporary file
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let temp_path = temp_file.path().to_str().unwrap();

        // Create key file using our new method
        let result = MockJwtConfig::create_test_key_file(temp_path);
        assert!(result.is_ok(), "Key file creation should succeed");

        // Verify the file exists and contains a valid key
        assert!(
            std::path::Path::new(temp_path).exists(),
            "Key file should exist"
        );

        let key_content =
            std::fs::read_to_string(temp_path).expect("Should be able to read key file");

        assert!(key_content.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(key_content
            .trim_end()
            .ends_with("-----END PRIVATE KEY-----"));
        assert!(key_content.len() > 200, "Key should be substantial length");

        // Verify it's different from a direct generation call
        let direct_key = MockJwtConfig::generate_test_private_key();
        assert_ne!(
            key_content, direct_key,
            "File key should be different from direct generation"
        );
    }
}
