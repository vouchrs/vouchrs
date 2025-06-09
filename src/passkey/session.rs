//! Passkey session management and related types
//!
//! This module handles passkey session creation, validation, and conversion
//! between different session formats

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::models::{VouchrsSession, VouchrsUserData};
use base64::Engine;
use webauthn_rs::prelude::AuthenticationResult;
use webauthn_rs::prelude::Credential;

/// Error types for passkey session operations
#[derive(Debug)]
pub enum PasskeySessionError {
    /// Authentication failed
    AuthenticationFailed(String),
    /// Session creation error
    SessionCreationFailed(String),
    /// `WebAuthn` error
    WebAuthnError(String),
    /// Other error
    OtherError(String),
}

impl std::fmt::Display for PasskeySessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasskeySessionError::AuthenticationFailed(msg) => {
                write!(f, "Authentication failed: {msg}")
            }
            PasskeySessionError::SessionCreationFailed(msg) => {
                write!(f, "Session creation failed: {msg}")
            }
            PasskeySessionError::WebAuthnError(err) => write!(f, "WebAuthn error: {err}"),
            PasskeySessionError::OtherError(msg) => write!(f, "Error: {msg}"),
        }
    }
}

impl std::error::Error for PasskeySessionError {}

/// Complete session data structure for passkey authentication
/// Equivalent to `CompleteSessionData` but for `WebAuthn` flows
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PasskeySessionData {
    // Common session data
    pub user_email: Option<String>,
    pub user_name: Option<String>,
    pub provider: String,
    pub provider_id: String, // Maps to user_handle
    pub authenticated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,

    // Passkey-specific authentication data
    pub credential_id: String,
}

impl PasskeySessionData {
    /// Convert to `VouchrsSession` for cookie storage
    #[must_use]
    pub fn to_session(&self) -> VouchrsSession {
        VouchrsSession {
            id_token: None,      // Passkeys don't use OAuth tokens
            refresh_token: None, // Passkeys don't refresh
            credential_id: Some(self.credential_id.clone()),
            user_handle: Some(self.provider_id.clone()),
            provider: self.provider.clone(),
            expires_at: self.expires_at,
            authenticated_at: self.authenticated_at,
        }
    }

    /// Convert to `VouchrsUserData` (identical to OAuth output)
    #[must_use]
    pub fn to_user_data(
        &self,
        client_ip: Option<&str>,
        user_agent_info: Option<&crate::utils::user_agent::UserAgentInfo>,
    ) -> VouchrsUserData {
        VouchrsUserData {
            email: self.user_email.clone().unwrap_or_default(),
            name: self.user_name.clone(),
            provider: self.provider.clone(),
            provider_id: self.provider_id.clone(),
            client_ip: client_ip.map(std::string::ToString::to_string),
            user_agent: user_agent_info.and_then(|ua| ua.user_agent.clone()),
            platform: user_agent_info.and_then(|ua| ua.platform.clone()),
            lang: user_agent_info.and_then(|ua| ua.lang.clone()),
            mobile: user_agent_info.map_or(0, |ua| i32::from(ua.mobile)),
            session_start: Some(self.authenticated_at.timestamp()),
        }
    }
}

/// Creates a passkey session from authentication result
///
/// # Arguments
/// * `auth_result` - The authentication result from `WebAuthn`
/// * `credential` - The credential used for authentication
/// * `user_email` - User's email address
/// * `user_name` - Optional user display name
/// * `session_duration` - Session duration in seconds
///
/// # Returns
/// * `Ok(PasskeySessionData)` - The created passkey session
/// * `Err(PasskeySessionError)` - If session creation fails
///
/// # Errors
/// Returns `PasskeySessionError` if the session creation fails
pub fn create_passkey_session(
    _auth_result: &AuthenticationResult,
    credential: &Credential,
    user_email: Option<&str>,
    user_name: Option<&str>,
    session_duration: i64,
) -> Result<PasskeySessionData, PasskeySessionError> {
    let now = Utc::now();

    // Create passkey session
    let session = PasskeySessionData {
        user_email: user_email.map(ToString::to_string),
        user_name: user_name.map(ToString::to_string),
        provider: "passkey".to_string(),
        provider_id: credential.counter.to_string(),
        credential_id: base64::engine::general_purpose::URL_SAFE
            .encode(credential.cred_id.as_ref()),
        authenticated_at: now,
        expires_at: now + Duration::seconds(session_duration),
    };

    Ok(session)
}

/// Converts a passkey session to `VouchrsSession` and `VouchrsUserData`
///
/// # Arguments
/// * `session` - The passkey session data
/// * `client_ip` - Optional client IP address
/// * `user_agent_info` - Optional user agent information
///
/// # Returns
/// * `(VouchrsSession, VouchrsUserData)` - The session and user data
pub fn to_vouchrs_session(
    session: &PasskeySessionData,
    client_ip: Option<&str>,
    user_agent_info: Option<&crate::utils::user_agent::UserAgentInfo>,
) -> (VouchrsSession, VouchrsUserData) {
    // Create VouchrsSession (compatible with OAuth flows)
    let vouchrs_session = VouchrsSession {
        id_token: None,
        refresh_token: None,
        credential_id: Some(session.credential_id.clone()),
        user_handle: Some(session.provider_id.clone()),
        provider: session.provider.clone(),
        expires_at: session.expires_at,
        authenticated_at: session.authenticated_at,
    };

    // Create VouchrsUserData (compatible with OAuth flows)
    let vouchrs_user_data = VouchrsUserData {
        email: session.user_email.clone().unwrap_or_default(),
        name: session.user_name.clone(),
        provider: session.provider.clone(),
        provider_id: session.provider_id.clone(),
        client_ip: client_ip.map(String::from),
        user_agent: user_agent_info.and_then(|ua| ua.user_agent.clone()),
        platform: user_agent_info.and_then(|ua| ua.platform.clone()),
        lang: user_agent_info.and_then(|ua| ua.lang.clone()),
        mobile: user_agent_info.map_or(0, |ua| i32::from(ua.mobile)),
        session_start: Some(session.authenticated_at.timestamp()),
    };

    (vouchrs_session, vouchrs_user_data)
}

/// Passkey session builder methods for creating `WebAuthn` sessions
pub struct PasskeySessionBuilder;

impl PasskeySessionBuilder {
    /// Create passkey session with same output format as OAuth
    ///
    /// # Errors
    ///
    /// Returns an error if the session duration calculation overflows or if required
    /// parameters are invalid.
    pub fn build_passkey_session(
        user_email: Option<String>,
        user_name: Option<String>,
        user_handle: String,
        credential_id: String,
        session_duration_hours: Option<u64>,
    ) -> Result<PasskeySessionData, String> {
        let now = Utc::now();
        let duration_hours = session_duration_hours.unwrap_or(168); // Default 7 days

        // Safely convert u64 to i64, preventing overflow
        let duration_hours_i64 =
            i64::try_from(duration_hours).map_err(|_| "Session duration too large".to_string())?;

        let expires_at = now + chrono::Duration::hours(duration_hours_i64);

        Ok(PasskeySessionData {
            user_email,
            user_name,
            provider: "passkey".to_string(),
            provider_id: user_handle,
            credential_id,
            authenticated_at: now,
            expires_at,
        })
    }

    /// Finalize passkey session with identical cookie output to OAuth
    #[must_use]
    pub fn finalize_passkey_session(
        req: &actix_web::HttpRequest,
        session_manager: &crate::session::SessionManager,
        passkey_session: &PasskeySessionData,
        redirect_url: Option<String>,
    ) -> actix_web::HttpResponse {
        use crate::utils::redirect_validator::validate_post_auth_redirect;

        // Extract client information (reuses OAuth logic)
        let (client_ip, user_agent_info) =
            crate::session_builder::SessionBuilder::extract_client_info(req);

        // Convert to standard session format
        let session = passkey_session.to_session();
        let user_data = passkey_session.to_user_data(client_ip.as_deref(), Some(&user_agent_info));

        // Create cookies using existing session manager
        match (
            session_manager.create_session_cookie(&session),
            session_manager.create_user_cookie(&user_data),
        ) {
            (Ok(session_cookie), Ok(user_cookie)) => {
                let redirect_to = redirect_url.unwrap_or_else(|| "/".to_string());

                // Validate the redirect URL to prevent open redirect attacks
                let validated_redirect = if let Ok(s) = validate_post_auth_redirect(&redirect_to) {
                    s.to_string()
                } else {
                    log::error!(
                        "Invalid post-authentication redirect URL '{redirect_to}': rejecting"
                    );
                    // Fallback to safe default on validation failure
                    "/".to_string()
                };

                crate::utils::response_builder::success_redirect_with_cookies(
                    &validated_redirect,
                    vec![session_cookie, user_cookie],
                )
            }
            _ => crate::session_builder::SessionBuilder::create_error_response(
                session_manager,
                "Failed to create session cookies",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passkey_session_creation() {
        let session_data = PasskeySessionBuilder::build_passkey_session(
            Some("user@example.com".to_string()),
            Some("John Doe".to_string()),
            "user_handle_123".to_string(),
            "credential_456".to_string(),
            Some(168), // 7 days
        )
        .expect("Passkey session should be created successfully");

        assert_eq!(
            session_data.user_email,
            Some("user@example.com".to_string())
        );
        assert_eq!(session_data.user_name, Some("John Doe".to_string()));
        assert_eq!(session_data.provider, "passkey");
        assert_eq!(session_data.provider_id, "user_handle_123");
        assert_eq!(session_data.credential_id, "credential_456");
        assert!(session_data.expires_at > session_data.authenticated_at);

        // Test conversion to VouchrsSession
        let session = session_data.to_session();
        assert_eq!(session.provider, "passkey");
        assert_eq!(session.credential_id, Some("credential_456".to_string()));
        assert_eq!(session.user_handle, Some("user_handle_123".to_string()));
        assert!(session.id_token.is_none());
        assert!(session.refresh_token.is_none());
    }

    #[test]
    fn test_passkey_session_user_data_conversion() {
        let session_data = PasskeySessionBuilder::build_passkey_session(
            Some("user@example.com".to_string()),
            Some("John Doe".to_string()),
            "user_handle_123".to_string(),
            "credential_456".to_string(),
            None, // Use default duration
        )
        .expect("Passkey session should be created successfully");

        let user_data = session_data.to_user_data(Some("192.168.1.1"), None);

        assert_eq!(user_data.email, "user@example.com");
        assert_eq!(user_data.name, Some("John Doe".to_string()));
        assert_eq!(user_data.provider, "passkey");
        assert_eq!(user_data.provider_id, "user_handle_123");
        assert_eq!(user_data.client_ip, Some("192.168.1.1".to_string()));
        assert_eq!(
            user_data.session_start,
            Some(session_data.authenticated_at.timestamp())
        );
    }

    #[test]
    fn test_usernameless_passkey_session_creation() {
        // Test creating a session without email or name (usernameless authentication)
        let session_data = PasskeySessionBuilder::build_passkey_session(
            None, // No email
            None, // No name
            "user_handle_123".to_string(),
            "credential_456".to_string(),
            Some(168), // 7 days
        )
        .expect("Usernameless passkey session should be created successfully");

        assert_eq!(session_data.user_email, None);
        assert_eq!(session_data.user_name, None);
        assert_eq!(session_data.provider, "passkey");
        assert_eq!(session_data.provider_id, "user_handle_123");
        assert_eq!(session_data.credential_id, "credential_456");
        assert!(session_data.expires_at > session_data.authenticated_at);

        // Test conversion to VouchrsUserData - should use empty string for email
        let user_data = session_data.to_user_data(Some("192.168.1.1"), None);
        assert_eq!(user_data.email, ""); // Should be empty string, not placeholder
        assert_eq!(user_data.name, None);
        assert_eq!(user_data.provider, "passkey");
        assert_eq!(user_data.provider_id, "user_handle_123");
        assert_eq!(user_data.client_ip, Some("192.168.1.1".to_string()));
        assert_eq!(
            user_data.session_start,
            Some(session_data.authenticated_at.timestamp())
        );
    }
}
