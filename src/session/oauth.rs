//! OAuth session utilities and logic
//!
//! This module provides utility functions for OAuth-specific session creation,
//! token processing, and result conversion. These are pure functions that
//! `SessionManager` can delegate to.

use crate::models::{VouchrsSession, VouchrsUserData};
use crate::oauth::{OAuthState, OAuthResult};
use crate::session::utils::extract_client_info;
use crate::utils::apple::AppleUserInfo;
use actix_web::HttpRequest;
use anyhow::Result;
use chrono::{DateTime, TimeZone, Utc};
use log::{debug, info, warn};
use serde_json::Value;

/// Create session objects from OAuth authentication result
///
/// # Errors
///
/// Returns an error if:
/// - Session creation fails due to invalid data in the OAuth result
/// - Client information extraction fails
pub fn create_oauth_session(
    oauth_result: &OauthResult,
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
) -> Result<OauthResult> {
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
) -> Result<VouchrsSession> {
    // Check if we have a refresh token
    let Some(refresh_token) = &session.refresh_token else {
        return Err(anyhow::anyhow!("No refresh token available"));
    };

    // Call the OAuth service to refresh the token
    let token_result = oauth_service
        .refresh_oauth_tokens(&session.provider, refresh_token)
        .await
        .map_err(|e| anyhow::anyhow!("OAuth token refresh failed: {e}"))?;

    // Return the refreshed session
    Ok(token_result.session)
}

#[cfg(test)]
mod tests {
    use super::create_oauth_session;
    use crate::testing::TestFixtures;
    use base64::Engine as _;
    use chrono::Utc;
    use serde_json::json;

    fn minimal_id_token(sub: &str) -> String {
        // JWT with only 'sub' claim, base64-encoded header and payload, signature ignored
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\"}");
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(format!(r#"{{"sub":"{sub}"}}"#).as_bytes());
        format!("{header}.{payload}.ignored")
    }

    #[test]
    fn test_create_oauth_session() {
        let oauth_result = TestFixtures::oauth_session_result();
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
}
