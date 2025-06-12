//! Authentication result structures for module separation
//!
//! This module defines lightweight result structures that authentication modules
//! return, which are directly converted to `VouchrsSession` and `VouchrsUserData`
//! by the session manager without intermediate abstractions.

use chrono::{DateTime, Utc};

/// Pure authentication result from OAuth flow - no session logic
#[derive(Debug, Clone)]
pub struct OauthResult {
    pub provider: String,
    pub provider_id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub authenticated_at: DateTime<Utc>,
    // OAuth-specific data
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
}

/// Pure authentication result from Passkey flow - no session logic
#[derive(Debug, Clone)]
pub struct PasskeyResult {
    pub provider: String,    // Always "passkey"
    pub provider_id: String, // user_handle
    pub email: Option<String>,
    pub name: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub authenticated_at: DateTime<Utc>,
    // Passkey-specific data
    pub credential_id: String,
    pub user_handle: String,
}
