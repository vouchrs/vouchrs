//! `WebAuthn` settings
//!
//! This module defines settings for `WebAuthn` passkey functionality.

use serde::{Deserialize, Serialize};

/// Passkey settings for `WebAuthn` operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeySettings {
    pub enabled: bool,
    pub rp_id: String,
    pub rp_name: String,
    pub rp_origin: String,
    pub timeout_seconds: u64,
    pub user_verification: String,
    pub authenticator_attachment: Option<String>,
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
        }
    }
}
