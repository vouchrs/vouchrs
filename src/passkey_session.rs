// Passkey session management for WebAuthn authentication
//
// This module provides passkey-specific session handling that produces identical
// session outputs to OAuth flows, enabling seamless upstream integration.
//
// Key Features:
// - PasskeySessionData model for WebAuthn session creation
// - Session builder methods for passkey authentication
// - Identical cookie output format to OAuth (VouchrsSession + VouchrsUserData)
// - Stateless design - no persistent storage in VouchRS

use crate::models::{VouchrsSession, VouchrsUserData};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Complete session data structure for passkey authentication
/// Equivalent to `CompleteSessionData` but for `WebAuthn` flows
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PasskeySessionData {
    // User identification (same as OAuth)
    pub user_email: String,
    pub user_name: Option<String>,
    pub provider: String,
    pub provider_id: String, // Maps to user_handle

    // Passkey-specific authentication data
    pub credential_id: String,
    pub authenticated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
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
            email: self.user_email.clone(),
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
        user_email: String,
        user_name: Option<String>,
        user_handle: String,
        credential_id: String,
        session_duration_hours: Option<u64>,
    ) -> Result<PasskeySessionData, String> {
        let now = Utc::now();
        let duration_hours = session_duration_hours.unwrap_or(168); // Default 7 days

        // Safely convert u64 to i64, preventing overflow
        let duration_hours_i64 = i64::try_from(duration_hours)
            .map_err(|_| "Session duration too large".to_string())?;

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
            "user@example.com".to_string(),
            Some("John Doe".to_string()),
            "user_handle_123".to_string(),
            "credential_456".to_string(),
            Some(168), // 7 days
        )
        .expect("Passkey session should be created successfully");

        assert_eq!(session_data.user_email, "user@example.com");
        assert_eq!(session_data.user_name, Some("John Doe".to_string()));
        assert_eq!(session_data.provider, "passkey");
        assert_eq!(session_data.provider_id, "user_handle_123");
        assert_eq!(session_data.credential_id, "credential_456");
        assert!(session_data.expires_at > session_data.authenticated_at);

        // Test conversion to VouchrsSession
        let session = session_data.to_session();
        assert!(session.is_passkey_session());
        assert!(!session.is_oauth_session());
        assert_eq!(session.provider, "passkey");
        assert_eq!(session.credential_id, Some("credential_456".to_string()));
        assert_eq!(session.user_handle, Some("user_handle_123".to_string()));
        assert!(session.id_token.is_none());
        assert!(session.refresh_token.is_none());
    }

    #[test]
    fn test_passkey_session_user_data_conversion() {
        let session_data = PasskeySessionBuilder::build_passkey_session(
            "user@example.com".to_string(),
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
    fn test_passkey_session_type_detection() {
        let session_data = PasskeySessionBuilder::build_passkey_session(
            "test@example.com".to_string(),
            Some("Test User".to_string()),
            "test_handle".to_string(),
            "test_credential".to_string(),
            None,
        )
        .expect("Passkey session should be created successfully");

        let session = session_data.to_session();

        // Test type detection methods
        assert!(session.is_passkey_session());
        assert!(!session.is_oauth_session());

        // Verify passkey-specific fields are set
        assert!(session.credential_id.is_some());
        assert!(session.user_handle.is_some());

        // Verify OAuth fields are not set
        assert!(session.id_token.is_none());
        assert!(session.refresh_token.is_none());
    }
}
