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
    /// Get `WebAuthn` settings from passkey settings
    #[must_use]
    pub fn to_webauthn_settings(&self) -> crate::webauthn::WebAuthnSettings {
        crate::webauthn::WebAuthnSettings {
            rp_id: self.rp_id.clone(),
            rp_name: self.rp_name.clone(),
            rp_origin: self.rp_origin.clone(),
            timeout_seconds: self.timeout_seconds,
            user_verification: self.user_verification.clone(),
            authenticator_attachment: self.authenticator_attachment.clone(),
        }
    }
}
