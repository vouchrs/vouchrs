//! Passkey settings
//!
//! This module defines settings for passkey functionality,
//! bridging between application settings and `WebAuthn` settings.

use serde::{Deserialize, Serialize};

/// Passkey settings for application integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeySettings {
    /// Whether passkeys are enabled
    pub enabled: bool,
    /// Relying Party ID (usually the domain)
    pub rp_id: String,
    /// Relying Party name (displayed to user)
    pub rp_name: String,
    /// Relying Party origin (e.g., <https://example.com>)
    pub rp_origin: String,
    /// Timeout in seconds for operations
    pub timeout_seconds: u64,
    /// User verification preference ("required", "preferred", "discouraged")
    pub user_verification: String,
    /// Optional authenticator attachment ("platform", "cross-platform")
    pub authenticator_attachment: Option<String>,
    /// Session duration in seconds
    pub session_duration_seconds: i64,
}

impl Default for PasskeySettings {
    fn default() -> Self {
        Self {
            enabled: false,
            rp_id: "localhost".to_string(),
            rp_name: "VouchRS".to_string(),
            rp_origin: "https://localhost".to_string(),
            timeout_seconds: 60,
            user_verification: "preferred".to_string(),
            authenticator_attachment: None,
            session_duration_seconds: 86400, // 24 hours
        }
    }
}

/// Convert `PasskeySettings` to `WebAuthn` settings
impl PasskeySettings {
    /// Create a webauthn-rs instance directly from settings
    ///
    /// This method converts our existing `PasskeySettings` configuration into a
    /// `webauthn_rs::Webauthn` instance that can be used for registration and authentication flows.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The `rp_origin` is not a valid URL
    /// - The `WebAuthn` builder fails to create a new instance (e.g., if the RP ID is not a valid suffix of the origin's domain)
    /// - The `WebAuthn` instance fails to build
    pub fn create_webauthn(&self) -> Result<webauthn_rs::Webauthn, anyhow::Error> {
        let rp_origin = url::Url::parse(&self.rp_origin)?;

        // Convert timeout from seconds to Duration
        let timeout = std::time::Duration::from_secs(self.timeout_seconds);

        let builder = webauthn_rs::WebauthnBuilder::new(&self.rp_id, &rp_origin)?
            .rp_name(&self.rp_name)
            .timeout(timeout);

        // Build and return the webauthn instance
        Ok(builder.build()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_create_webauthn() {
        let settings = PasskeySettings {
            enabled: true,
            rp_id: "example.com".to_string(),
            rp_name: "Example Service".to_string(),
            rp_origin: "https://example.com".to_string(),
            timeout_seconds: 60,
            user_verification: "preferred".to_string(),
            authenticator_attachment: None,
            session_duration_seconds: 3600,
        };

        // Test the WebAuthn instance creation
        let result = settings.create_webauthn();
        assert!(
            result.is_ok(),
            "Failed to create WebAuthn instance: {result:?}"
        );

        // Check invalid origin
        let mut invalid_settings = settings.clone();
        invalid_settings.rp_origin = "not-a-valid-url".to_string();
        let invalid_result = invalid_settings.create_webauthn();
        assert!(invalid_result.is_err(), "Should fail with invalid origin");

        // Check invalid combination (if origin doesn't match rp_id)
        let mut mismatch_settings = settings.clone();
        mismatch_settings.rp_origin = "https://different-domain.com".to_string();
        let mismatch_result = mismatch_settings.create_webauthn();
        // WebAuthn library enforces that rp_id is a suffix of the origin's domain
        assert!(
            mismatch_result.is_err(),
            "Should fail when origin domain doesn't match rp_id"
        );
    }
}
