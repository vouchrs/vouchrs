//! Passkey session management and related types
//!
//! This module handles passkey session creation, validation, and conversion
//! between different session formats

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::models::{VouchrsSession, VouchrsUserData};
use crate::session::utils::extract_client_info;
use actix_web::HttpRequest;
use anyhow::Result;
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

/// Create session objects from Passkey authentication result
///
/// This utility function converts Passkey authentication results into session objects
/// that `SessionManager` can use to create HTTP responses with cookies.
///
/// # Arguments
/// * `passkey_result` - The passkey authentication result
/// * `req` - The HTTP request for client information extraction
/// * `bind_session_to_ip` - Whether to bind the session to client IP
///
/// # Returns
/// * `Ok((VouchrsSession, VouchrsUserData))` if successful
/// * `Err(String)` if session creation fails
///
/// # Errors
/// Returns an error if:
/// - Session creation fails due to invalid data in the Passkey result
/// - Client information extraction fails
pub fn create_passkey_session_from_result(
    passkey_result: &crate::passkey::PasskeyResult,
    req: &HttpRequest,
    bind_session_to_ip: bool,
) -> Result<(VouchrsSession, VouchrsUserData), String> {
    let (client_ip, user_agent_info) = extract_client_info(req);

    let session = VouchrsSession {
        // No OAuth fields
        id_token: None,
        refresh_token: None,

        // Passkey-specific fields
        credential_id: Some(passkey_result.credential_id.clone()),
        user_handle: Some(passkey_result.user_handle.clone()),

        // Common fields
        provider: passkey_result.provider.clone(),
        expires_at: passkey_result.expires_at,
        authenticated_at: passkey_result.authenticated_at,
        client_ip: if bind_session_to_ip {
            client_ip.clone()
        } else {
            None
        },
    };

    let user_data = VouchrsUserData {
        email: passkey_result.email.clone().unwrap_or_default(),
        name: passkey_result.name.clone(),
        provider: passkey_result.provider.clone(),
        provider_id: passkey_result.provider_id.clone(),
        client_ip,
        user_agent: user_agent_info.user_agent,
        platform: user_agent_info.platform,
        lang: user_agent_info.lang,
        mobile: i32::from(user_agent_info.mobile),
        session_start: Some(passkey_result.authenticated_at.timestamp()),
    };

    Ok((session, user_data))
}

/// Complete session data structure for passkey authentication
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
            client_ip: None, // Will be set during session creation based on configuration
        }
    }

    /// Convert to `VouchrsUserData` for session cookies
    #[must_use]
    pub fn to_user_data(
        &self,
        client_ip: Option<&str>,
        user_agent_info: Option<&crate::utils::headers::UserAgentInfo>,
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
    user_agent_info: Option<&crate::utils::headers::UserAgentInfo>,
) -> (VouchrsSession, VouchrsUserData) {
    // Create VouchrsSession for cookie storage
    let vouchrs_session = VouchrsSession {
        id_token: None,
        refresh_token: None,
        credential_id: Some(session.credential_id.clone()),
        user_handle: Some(session.provider_id.clone()),
        provider: session.provider.clone(),
        expires_at: session.expires_at,
        authenticated_at: session.authenticated_at,
        client_ip: client_ip.map(std::string::ToString::to_string),
    };

    // Create VouchrsUserData for cookie storage
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

/// Validate passkey result for session creation
///
/// Utility function to validate that a passkey result has the required fields
/// for successful session creation.
///
/// # Arguments
/// * `passkey_result` - The passkey result to validate
///
/// # Returns
/// * `Ok(())` if validation passes
/// * `Err(String)` with validation error message
///
/// # Errors
/// Returns an error if:
/// - Required fields are missing or empty
/// - Session is already expired
/// - Authentication time is invalid
pub fn validate_passkey_result_for_session(
    passkey_result: &crate::passkey::PasskeyResult,
) -> Result<(), String> {
    // Check required fields
    if passkey_result.provider.is_empty() {
        return Err("Provider is required".to_string());
    }

    if passkey_result.provider_id.is_empty() {
        return Err("Provider ID is required".to_string());
    }

    if passkey_result.credential_id.is_empty() {
        return Err("Credential ID is required".to_string());
    }

    if passkey_result.user_handle.is_empty() {
        return Err("User handle is required".to_string());
    }

    // Check token expiration
    let now = chrono::Utc::now();
    if passkey_result.expires_at <= now {
        return Err("Passkey session is already expired".to_string());
    }

    // Validate authentication time
    if passkey_result.authenticated_at > now {
        return Err("Authentication time cannot be in the future".to_string());
    }

    Ok(())
}

/// Extract passkey authentication information from session
///
/// Utility function to extract and validate passkey authentication information from a session.
///
/// # Arguments
/// * `session` - The session to extract passkey info from
///
/// # Returns
/// * `Ok((credential_id, user_handle))` if valid passkey session
/// * `Err(String)` if session is invalid or missing required data
///
/// # Errors
/// Returns an error if:
/// - Session is not a passkey session
/// - Required credential ID or user handle is missing
pub fn extract_passkey_auth_info(session: &VouchrsSession) -> Result<(String, String), String> {
    // Validate this is a passkey session
    if !session.is_passkey_session() {
        return Err("Not a passkey session".to_string());
    }

    // Extract credential ID
    let credential_id = session
        .credential_id
        .as_ref()
        .ok_or("No credential ID available")?;

    // Extract user handle
    let user_handle = session
        .user_handle
        .as_ref()
        .ok_or("No user handle available")?;

    Ok((credential_id.clone(), user_handle.clone()))
}

/// Create minimal passkey result for testing or fallback scenarios
///
/// Utility function to create a minimal passkey result with default values.
/// Useful for testing or creating fallback authentication results.
///
/// # Arguments
/// * `user_handle` - User handle for the passkey
/// * `credential_id` - Credential ID for the passkey
/// * `email` - Optional user email address
///
/// # Returns
/// * `PasskeyResult` with minimal required fields
#[must_use]
pub fn create_minimal_passkey_result(
    user_handle: &str,
    credential_id: &str,
    email: Option<&str>,
) -> crate::passkey::PasskeyResult {
    let now = chrono::Utc::now();

    crate::passkey::PasskeyResult {
        provider: "passkey".to_string(),
        provider_id: user_handle.to_string(),
        email: email.map(ToString::to_string),
        name: None,
        expires_at: now + chrono::Duration::hours(168), // 7 days default
        authenticated_at: now,
        credential_id: credential_id.to_string(),
        user_handle: user_handle.to_string(),
    }
}

/// Convert `PasskeySessionData` to standard session objects
///
/// Utility function that provides a cleaner interface for converting internal
/// `PasskeySessionData` to the standard `VouchrsSession` and `VouchrsUserData` objects.
///
/// # Arguments
/// * `session_data` - The passkey session data to convert
/// * `req` - HTTP request for client information extraction
/// * `bind_session_to_ip` - Whether to bind session to client IP
///
/// # Returns
/// * `(VouchrsSession, VouchrsUserData)` tuple
#[must_use]
pub fn convert_passkey_session_data(
    session_data: &PasskeySessionData,
    req: &HttpRequest,
    bind_session_to_ip: bool,
) -> (VouchrsSession, VouchrsUserData) {
    let (client_ip, user_agent_info) = extract_client_info(req);

    let session = VouchrsSession {
        id_token: None,
        refresh_token: None,
        credential_id: Some(session_data.credential_id.clone()),
        user_handle: Some(session_data.provider_id.clone()),
        provider: session_data.provider.clone(),
        expires_at: session_data.expires_at,
        authenticated_at: session_data.authenticated_at,
        client_ip: if bind_session_to_ip {
            client_ip.clone()
        } else {
            None
        },
    };

    let user_data = VouchrsUserData {
        email: session_data.user_email.clone().unwrap_or_default(),
        name: session_data.user_name.clone(),
        provider: session_data.provider.clone(),
        provider_id: session_data.provider_id.clone(),
        client_ip,
        user_agent: user_agent_info.user_agent,
        platform: user_agent_info.platform,
        lang: user_agent_info.lang,
        mobile: i32::from(user_agent_info.mobile),
        session_start: Some(session_data.authenticated_at.timestamp()),
    };

    (session, user_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passkey_session_creation() {
        let now = Utc::now();
        let session_data = PasskeySessionData {
            user_email: Some("user@example.com".to_string()),
            user_name: Some("John Doe".to_string()),
            provider: "passkey".to_string(),
            provider_id: "user_handle_123".to_string(),
            credential_id: "credential_456".to_string(),
            authenticated_at: now,
            expires_at: now + chrono::Duration::hours(168), // 7 days
        };

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
        let now = Utc::now();
        let session_data = PasskeySessionData {
            user_email: Some("user@example.com".to_string()),
            user_name: Some("John Doe".to_string()),
            provider: "passkey".to_string(),
            provider_id: "user_handle_123".to_string(),
            credential_id: "credential_456".to_string(),
            authenticated_at: now,
            expires_at: now + chrono::Duration::hours(168), // Default 7 days
        };

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
        let now = Utc::now();
        let session_data = PasskeySessionData {
            user_email: None, // No email
            user_name: None,  // No name
            provider: "passkey".to_string(),
            provider_id: "user_handle_123".to_string(),
            credential_id: "credential_456".to_string(),
            authenticated_at: now,
            expires_at: now + chrono::Duration::hours(168), // 7 days
        };

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

    #[test]
    fn test_create_passkey_session_from_result() {
        let passkey_result = crate::passkey::PasskeyResult {
            provider: "passkey".to_string(),
            provider_id: "user_handle_123".to_string(),
            email: Some("user@example.com".to_string()),
            name: Some("John Doe".to_string()),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(168),
            authenticated_at: chrono::Utc::now(),
            credential_id: "credential_456".to_string(),
            user_handle: "user_handle_123".to_string(),
        };

        let req = crate::testing::RequestBuilder::new().build();

        let result = create_passkey_session_from_result(&passkey_result, &req, false);
        assert!(result.is_ok());

        let (session, user_data) = result.unwrap();
        assert_eq!(session.provider, "passkey");
        assert_eq!(session.credential_id, Some("credential_456".to_string()));
        assert_eq!(session.user_handle, Some("user_handle_123".to_string()));
        assert_eq!(user_data.email, "user@example.com");
        assert_eq!(user_data.provider_id, "user_handle_123");
    }

    #[test]
    fn test_validate_passkey_result_for_session() {
        let valid_result = crate::passkey::PasskeyResult {
            provider: "passkey".to_string(),
            provider_id: "user_handle_123".to_string(),
            email: Some("user@example.com".to_string()),
            name: Some("John Doe".to_string()),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(168),
            authenticated_at: chrono::Utc::now(),
            credential_id: "credential_456".to_string(),
            user_handle: "user_handle_123".to_string(),
        };

        // Valid result should pass validation
        assert!(validate_passkey_result_for_session(&valid_result).is_ok());

        // Empty provider should fail
        let mut invalid_result = valid_result.clone();
        invalid_result.provider = String::new();
        assert!(validate_passkey_result_for_session(&invalid_result).is_err());

        // Expired session should fail
        let mut expired_result = valid_result.clone();
        expired_result.expires_at = chrono::Utc::now() - chrono::Duration::hours(1);
        assert!(validate_passkey_result_for_session(&expired_result).is_err());
    }

    #[test]
    fn test_extract_passkey_auth_info() {
        let mut session = crate::testing::TestFixtures::oauth_session();

        // OAuth session should fail
        assert!(extract_passkey_auth_info(&session).is_err());

        // Convert to passkey session
        session.id_token = None;
        session.refresh_token = None;
        session.credential_id = Some("credential_456".to_string());
        session.user_handle = Some("user_handle_123".to_string());

        // Passkey session should succeed
        let result = extract_passkey_auth_info(&session);
        assert!(result.is_ok());

        let (credential_id, user_handle) = result.unwrap();
        assert_eq!(credential_id, "credential_456");
        assert_eq!(user_handle, "user_handle_123");
    }

    #[test]
    fn test_create_minimal_passkey_result() {
        let result = create_minimal_passkey_result(
            "user_handle_123",
            "credential_456",
            Some("user@example.com"),
        );

        assert_eq!(result.provider, "passkey");
        assert_eq!(result.provider_id, "user_handle_123");
        assert_eq!(result.credential_id, "credential_456");
        assert_eq!(result.user_handle, "user_handle_123");
        assert_eq!(result.email, Some("user@example.com".to_string()));
        assert!(result.expires_at > chrono::Utc::now());
    }
}
