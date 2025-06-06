//! `WebAuthn` settings implementation
//!
//! This module defines settings for `WebAuthn` operations independent
//! of application-specific settings.

use serde::{Deserialize, Serialize};

/// `WebAuthn` settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnSettings {
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
}

impl Default for WebAuthnSettings {
    fn default() -> Self {
        Self {
            rp_id: "localhost".to_string(),
            rp_name: "VouchRS".to_string(),
            rp_origin: "https://localhost".to_string(),
            timeout_seconds: 60,
            user_verification: "preferred".to_string(),
            authenticator_attachment: None,
        }
    }
}
