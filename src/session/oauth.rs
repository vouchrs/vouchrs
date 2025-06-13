//! OAuth session utilities and logic
//!
//! This module provides utility functions for OAuth-specific session creation,
//! token processing, and result conversion. These are pure functions that
//! `SessionManager` can delegate to.

use crate::models::{VouchrsSession, VouchrsUserData};
use crate::oauth::{OAuthResult, OAuthState};
use crate::session::utils::extract_client_info;
use crate::utils::apple::AppleUserInfo;
use actix_web::HttpRequest;
use anyhow::Result;
use log::info;

/// Create session objects from OAuth authentication result
///
/// This utility function converts OAuth authentication results into session objects
/// that `SessionManager` can use to create HTTP responses with cookies.
///
/// # Errors
///
/// Returns an error if:
/// - Session creation fails due to invalid data in the OAuth result
/// - Client information extraction fails
pub fn create_oauth_session(
    oauth_result: &OAuthResult,
    req: &HttpRequest,
    bind_session_to_ip: bool,
) -> Result<(VouchrsSession, VouchrsUserData)> {
    let (client_ip, user_agent_info) = extract_client_info(req);

    let session = VouchrsSession {
        // OAuth-specific fields
        id_token: oauth_result.id_token.clone(),
        refresh_token: oauth_result.refresh_token.clone(),

        // No passkey fields
        credential_id: None,
        user_handle: None,

        // Common fields
        provider: oauth_result.provider.clone(),
        expires_at: oauth_result.expires_at,
        authenticated_at: oauth_result.authenticated_at,
        client_ip: if bind_session_to_ip {
            client_ip.clone()
        } else {
            None
        },
    };

    let user_data = VouchrsUserData {
        email: oauth_result.email.clone().unwrap_or_default(),
        name: oauth_result.name.clone(),
        provider: oauth_result.provider.clone(),
        provider_id: oauth_result.provider_id.clone(),
        client_ip,
        user_agent: user_agent_info.user_agent,
        platform: user_agent_info.platform,
        lang: user_agent_info.lang,
        mobile: i32::from(user_agent_info.mobile),
        session_start: Some(oauth_result.authenticated_at.timestamp()),
    };

    Ok((session, user_data))
}

/// Process OAuth callback and create authentication result
///
/// # Errors
///
/// Returns an error if:
/// - The OAuth service fails to exchange the authorization code
/// - Token validation fails
/// - Required user information is missing or invalid
pub async fn process_oauth_callback(
    provider: &str,
    code: &str,
    state: &OAuthState,
    apple_info: Option<AppleUserInfo>,
    oauth_service: &dyn crate::oauth::OAuthAuthenticationService,
) -> Result<OAuthResult> {
    info!("Processing OAuth callback for provider: {provider}");

    // Call OAuth service to get OAuth result (no session creation)
    let oauth_result = oauth_service
        .process_oauth_callback(provider, code, state, apple_info)
        .await
        .map_err(|e| {
            log::error!("OAuth callback processing failed: {e}");
            anyhow::anyhow!("OAuth authentication failed: {e}")
        })?;

    Ok(oauth_result)
}

/// Validate OAuth tokens and create session
///
/// # Errors
///
/// Returns an error if:
/// - The session doesn't have a refresh token
/// - The OAuth service fails to refresh the token
/// - Token validation fails
pub async fn handle_oauth_token_refresh(
    session: &VouchrsSession,
    oauth_service: &dyn crate::oauth::OAuthAuthenticationService,
) -> Result<OAuthResult> {
    // Check if we have a refresh token
    let Some(refresh_token) = &session.refresh_token else {
        return Err(anyhow::anyhow!("No refresh token available"));
    };

    // Call the OAuth service to refresh the token
    let oauth_result = oauth_service
        .refresh_oauth_tokens(&session.provider, refresh_token)
        .await
        .map_err(|e| anyhow::anyhow!("OAuth token refresh failed: {e}"))?;

    // Return the refreshed OAuth result
    Ok(oauth_result)
}

/// Validate OAuth session for token refresh requirements
///
/// This utility function checks if an OAuth session needs token refresh and validates
/// that the session has the necessary tokens for refresh operations.
///
/// # Arguments
/// * `session` - The OAuth session to validate
///
/// # Returns
/// * `Ok(true)` if refresh is needed and possible
/// * `Ok(false)` if refresh is not needed
/// * `Err(String)` if refresh is needed but not possible
///
/// # Errors
///
/// Returns an error if:
/// - The session is not an OAuth session
/// - Token refresh is needed but no refresh token is available
pub fn validate_oauth_refresh_requirements(session: &VouchrsSession) -> Result<bool, String> {
    // Check if this is an OAuth session
    if !session.is_oauth_session() {
        return Err("Not an OAuth session".to_string());
    }

    // Check if tokens need refresh using the validation module
    let needs_refresh = crate::session::validation::needs_token_refresh(session);

    if needs_refresh {
        // Validate that we have a refresh token
        if session.refresh_token.is_none() {
            return Err("Token refresh needed but no refresh token available".to_string());
        }
    }

    Ok(needs_refresh)
}

/// Extract OAuth provider information from session
///
/// Utility function to extract and validate OAuth provider information from a session.
///
/// # Arguments
/// * `session` - The session to extract provider info from
///
/// # Returns
/// * `Ok((provider, refresh_token))` if valid OAuth session with refresh token
/// * `Err(String)` if session is invalid or missing required data
///
/// # Errors
///
/// Returns an error if:
/// - The session is not an OAuth session
/// - No refresh token is available in the session
pub fn extract_oauth_provider_info(session: &VouchrsSession) -> Result<(String, String), String> {
    // Validate this is an OAuth session
    if !session.is_oauth_session() {
        return Err("Not an OAuth session".to_string());
    }

    // Extract refresh token
    let refresh_token = session
        .refresh_token
        .as_ref()
        .ok_or("No refresh token available")?;

    Ok((session.provider.clone(), refresh_token.clone()))
}

/// Create minimal OAuth result for testing or fallback scenarios
///
/// Utility function to create a minimal OAuth result with default values.
/// Useful for testing or creating fallback authentication results.
///
/// # Arguments
/// * `provider` - OAuth provider name
/// * `provider_id` - Provider-specific user ID
/// * `email` - User email address
///
/// # Returns
/// * `OAuthResult` with minimal required fields
#[must_use]
pub fn create_minimal_oauth_result(
    provider: &str,
    provider_id: &str,
    email: Option<&str>,
) -> OAuthResult {
    let now = chrono::Utc::now();

    OAuthResult {
        provider: provider.to_string(),
        provider_id: provider_id.to_string(),
        email: email.map(ToString::to_string),
        name: None,
        expires_at: now + chrono::Duration::hours(1), // 1 hour default
        authenticated_at: now,
        id_token: None,
        refresh_token: None,
    }
}

/// Validate OAuth result for session creation
///
/// Utility function to validate that an OAuth result has the required fields
/// for successful session creation.
///
/// # Arguments
/// * `oauth_result` - The OAuth result to validate
///
/// # Returns
/// * `Ok(())` if validation passes
/// * `Err(String)` with validation error message
///
/// # Errors
///
/// Returns an error if:
/// - Provider name is empty
/// - Provider ID is empty
/// - OAuth tokens are already expired
/// - Authentication time is in the future
pub fn validate_oauth_result_for_session(oauth_result: &OAuthResult) -> Result<(), String> {
    // Check required fields
    if oauth_result.provider.is_empty() {
        return Err("Provider is required".to_string());
    }

    if oauth_result.provider_id.is_empty() {
        return Err("Provider ID is required".to_string());
    }

    // Check token expiration
    let now = chrono::Utc::now();
    if oauth_result.expires_at <= now {
        return Err("OAuth tokens are already expired".to_string());
    }

    // Validate authentication time
    if oauth_result.authenticated_at > now {
        return Err("Authentication time cannot be in the future".to_string());
    }

    Ok(())
}

/// Reconstruct session from OAuth result after token refresh
///
/// This utility function creates a new `VouchrsSession` from an OAuth result,
/// preserving the original session structure while updating tokens and timestamps.
///
/// # Arguments
/// * `oauth_result` - The OAuth result containing updated tokens
/// * `original_session` - The original session to preserve structure from
/// * `ip_binding_enabled` - Whether IP binding is enabled for the session
///
/// # Returns
/// * `VouchrsSession` with updated OAuth tokens and timestamps
#[must_use]
pub fn reconstruct_session_from_oauth_result(
    oauth_result: &OAuthResult,
    original_session: &VouchrsSession,
    ip_binding_enabled: bool,
) -> VouchrsSession {
    VouchrsSession {
        // Updated OAuth tokens from refresh
        id_token: oauth_result.id_token.clone(),
        refresh_token: oauth_result.refresh_token.clone(),
        expires_at: oauth_result.expires_at,
        authenticated_at: oauth_result.authenticated_at,

        // Preserve non-OAuth fields from original session
        credential_id: original_session.credential_id.clone(),
        user_handle: original_session.user_handle.clone(),
        provider: original_session.provider.clone(),

        // Preserve client IP based on binding settings
        client_ip: if ip_binding_enabled {
            original_session.client_ip.clone()
        } else {
            None
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use chrono::Utc;

    fn minimal_id_token(sub: &str) -> String {
        // JWT with only 'sub' claim, base64-encoded header and payload, signature ignored
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\"}");
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(format!(r#"{{"sub":"{sub}"}}"#).as_bytes());
        format!("{header}.{payload}.ignored")
    }

    #[test]
    fn test_create_oauth_session() {
        let oauth_result =
            create_minimal_oauth_result("google", "google_user_123", Some("user@example.com"));
        let req = crate::testing::RequestBuilder::new().build();

        let result = create_oauth_session(&oauth_result, &req, false);
        assert!(result.is_ok());

        let (session, user_data) = result.unwrap();
        assert_eq!(session.provider, oauth_result.provider);
        assert_eq!(user_data.email, oauth_result.email.unwrap_or_default());
    }

    #[test]
    fn test_process_id_token_with_apple_info() {
        let id_token_str = minimal_id_token("apple-sub-123");
        let refresh_token = Some("refresh123".to_string());
        let expires_at = Utc::now() + chrono::Duration::hours(1);
        let apple_user_info = crate::utils::apple::AppleUserInfo {
            name: crate::utils::apple::AppleUserName {
                first_name: Some("Jane".to_string()),
                last_name: Some("Doe".to_string()),
            },
            email: Some("jane.doe@apple.com".to_string()),
        };

        let result = crate::oauth::tokens::process_id_token(
            "apple",
            Some(&id_token_str),
            refresh_token,
            expires_at,
            Some(&apple_user_info),
        )
        .expect("OAuth result should be created");

        assert_eq!(result.email.unwrap(), "jane.doe@apple.com");
        assert_eq!(result.name.unwrap(), "Jane Doe");
        assert_eq!(result.provider, "apple");
        assert_eq!(result.provider_id, "apple-sub-123");
        assert!(result.id_token.is_some());
        assert!(result.refresh_token.is_some());
    }

    #[test]
    fn test_validate_oauth_refresh_requirements() {
        let mut session = crate::testing::TestFixtures::oauth_session();

        // Session that needs refresh and has refresh token should return Ok(true)
        session.expires_at = chrono::Utc::now() + chrono::Duration::minutes(2);
        session.refresh_token = Some("refresh_token".to_string());
        let result = validate_oauth_refresh_requirements(&session);
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Session that doesn't need refresh should return Ok(false)
        session.expires_at = chrono::Utc::now() + chrono::Duration::hours(2);
        let result = validate_oauth_refresh_requirements(&session);
        assert!(result.is_ok());
        assert!(!result.unwrap());

        // Session that needs refresh but has no refresh token should return error
        session.expires_at = chrono::Utc::now() + chrono::Duration::minutes(2);
        session.refresh_token = None;
        let result = validate_oauth_refresh_requirements(&session);
        assert!(result.is_err());

        // Non-OAuth session should return error
        session.id_token = None;
        session.refresh_token = None;
        session.credential_id = Some("credential_id".to_string());
        let result = validate_oauth_refresh_requirements(&session);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_oauth_provider_info() {
        let mut session = crate::testing::TestFixtures::oauth_session();
        session.provider = "google".to_string();
        session.refresh_token = Some("refresh_token_123".to_string());

        let result = extract_oauth_provider_info(&session);
        assert!(result.is_ok());

        let (provider, refresh_token) = result.unwrap();
        assert_eq!(provider, "google");
        assert_eq!(refresh_token, "refresh_token_123");

        // Session without refresh token should fail
        session.refresh_token = None;
        assert!(extract_oauth_provider_info(&session).is_err());
    }

    #[test]
    fn test_create_minimal_oauth_result() {
        let result =
            create_minimal_oauth_result("google", "google_user_123", Some("user@example.com"));

        assert_eq!(result.provider, "google");
        assert_eq!(result.provider_id, "google_user_123");
        assert_eq!(result.email, Some("user@example.com".to_string()));
        assert!(result.expires_at > chrono::Utc::now());
        assert!(result.authenticated_at <= chrono::Utc::now());
    }

    #[test]
    fn test_validate_oauth_result_for_session() {
        let valid_result =
            create_minimal_oauth_result("google", "google_user_123", Some("user@example.com"));

        // Valid result should pass
        assert!(validate_oauth_result_for_session(&valid_result).is_ok());

        // Empty provider should fail
        let mut invalid_result = valid_result.clone();
        invalid_result.provider = String::new();
        assert!(validate_oauth_result_for_session(&invalid_result).is_err());

        // Empty provider_id should fail
        let mut invalid_result = valid_result.clone();
        invalid_result.provider_id = String::new();
        assert!(validate_oauth_result_for_session(&invalid_result).is_err());

        // Expired tokens should fail
        let mut expired_result = valid_result.clone();
        expired_result.expires_at = chrono::Utc::now() - chrono::Duration::hours(1);
        assert!(validate_oauth_result_for_session(&expired_result).is_err());

        // Future authentication time should fail
        let mut future_result = valid_result.clone();
        future_result.authenticated_at = chrono::Utc::now() + chrono::Duration::hours(1);
        assert!(validate_oauth_result_for_session(&future_result).is_err());
    }
}
