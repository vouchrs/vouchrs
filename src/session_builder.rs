// Session builder for creating VouchrSession from ID token claims
//
// This module provides a unified approach for extracting user information from OAuth ID tokens
// and mapping them to VouchrSession fields. It replaces the complex provider-specific extraction
// logic with a standardized approach that works with all OAuth providers that issue standard
// OpenID Connect ID tokens.
//
// Standard ID Token Claims Mapping:
// - sub (subject) -> provider_id: Unique identifier for the user from the provider
// - email -> user_email: User's email address
// - iat (issued at) -> created_at: When the token was issued
// - exp (expires) -> expires_at: When the token expires
// - iss (issuer) -> provider: OAuth provider (normalized from issuer URL)
// - name, given_name+family_name -> user_name: User's display name (optional)

use crate::utils::crypto::decode_jwt_payload;
use crate::models::CompleteSessionData;
use crate::utils::apple::AppleUserInfo;
use chrono::{DateTime, TimeZone, Utc};
use log::{debug, info, warn};
use serde_json::Value;

/// Contains all OAuth-related data for session creation
#[derive(Debug, Clone)]
pub struct AuthenticationData {
    /// OAuth provider name
    pub provider: String,
    /// ID token from OAuth provider
    pub id_token: Option<String>,
    /// Refresh token from OAuth provider
    pub refresh_token: Option<String>,
    /// Token expiration time
    pub expires_at: DateTime<Utc>,
    /// Additional user info for Apple Sign In
    pub apple_user_info: Option<AppleUserInfo>,
}

impl AuthenticationData {
    /// Creates a new authentication data object with the given parameters
    pub fn new(
        provider: &str,
        id_token: Option<String>,
        refresh_token: Option<String>,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            provider: provider.to_string(),
            id_token,
            refresh_token,
            expires_at,
            apple_user_info: None,
        }
    }
    
    /// Sets the Apple user info
    pub fn with_apple_info(mut self, apple_user_info: Option<AppleUserInfo>) -> Self {
        self.apple_user_info = apple_user_info;
        self
    }
}

pub struct SessionFinalizationBuilder<'a> {
    req: &'a actix_web::HttpRequest,
    session_manager: &'a crate::session::SessionManager,
    auth_data: AuthenticationData,
    redirect_url: Option<String>,
}

impl<'a> SessionFinalizationBuilder<'a> {
    /// Creates a new session finalization builder with required parameters
    pub fn new(
        req: &'a actix_web::HttpRequest,
        session_manager: &'a crate::session::SessionManager,
        provider: &str,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            req,
            session_manager,
            auth_data: AuthenticationData::new(provider, None, None, expires_at),
            redirect_url: None,
        }
    }

    /// Sets the ID token for the session
    pub fn with_id_token(mut self, id_token: Option<String>) -> Self {
        self.auth_data.id_token = id_token;
        self
    }

    /// Sets the refresh token for the session
    pub fn with_refresh_token(mut self, refresh_token: Option<String>) -> Self {
        self.auth_data.refresh_token = refresh_token;
        self
    }

    /// Sets the Apple user info for the session
    pub fn with_apple_user_info(mut self, apple_user_info: Option<AppleUserInfo>) -> Self {
        self.auth_data.apple_user_info = apple_user_info;
        self
    }

    /// Sets the redirect URL for after authentication
    pub fn with_redirect_url(mut self, redirect_url: Option<String>) -> Self {
        self.redirect_url = redirect_url;
        self
    }

    /// Finalizes the session and returns an HTTP response with session cookies
    pub fn finalize(self) -> actix_web::HttpResponse {
        SessionBuilder::finalize_session(
            self.req,
            self.session_manager,
            &self.auth_data,
            self.redirect_url,
        )
    }
}

pub struct SessionBuilder;

impl SessionBuilder {
    /// Example method showing how to use the SessionFinalizationBuilder
    /// 
    /// # Example
    /// 
    /// ```rust,ignore
    /// let response = SessionBuilder::finalize_session_with_builder(
    ///     req,
    ///     session_manager,
    ///     "google",
    ///     expires_at
    /// )
    /// .with_id_token(Some(id_token))
    /// .with_refresh_token(Some(refresh_token))
    /// .finalize();
    /// ```
    pub fn finalize_session_with_builder<'a>(
        req: &'a actix_web::HttpRequest,
        session_manager: &'a crate::session::SessionManager,
        provider: &str,
        expires_at: DateTime<Utc>,
    ) -> SessionFinalizationBuilder<'a> {
        SessionFinalizationBuilder::new(req, session_manager, provider, expires_at)
    }
    
    /// Creates a `CompleteSessionData` from OAuth tokens, extracting standard claims from the ID token
    /// and using Apple user info to fill in missing fields if available
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The ID token is missing or invalid
    /// - JWT decoding fails
    /// - Required claims are missing from the token
    pub fn build_session(
        provider: String,
        id_token: Option<String>,
        refresh_token: Option<String>,
        expires_at: DateTime<Utc>,
    ) -> Result<CompleteSessionData, String> {
        Self::build_session_with_apple_info(provider, id_token, refresh_token, expires_at, None)
    }

    /// Creates a `CompleteSessionData` from OAuth tokens with optional Apple user info for fallback
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The ID token is missing or invalid
    /// - JWT decoding fails
    /// - Required claims are missing from the token
    ///
    /// # Panics
    ///
    /// This function panics if it cannot provide a fallback email address. However, the current
    /// implementation always provides a default email, making panics unlikely.
    #[allow(clippy::needless_pass_by_value)]
    pub fn build_session_with_apple_info(
        provider: String,
        id_token: Option<String>,
        refresh_token: Option<String>,
        expires_at: DateTime<Utc>,
        apple_user_info: Option<AppleUserInfo>,
    ) -> Result<CompleteSessionData, String> {
        let id_token_ref = id_token.as_ref().ok_or("No ID token available")?;

        let claims = decode_jwt_payload(id_token_ref)
            .map_err(|e| format!("Failed to decode ID token: {e}"))?;

        info!(
            "Building session from ID token claims for provider: {provider}"
        );
        debug!(
            "ID token claims: {}",
            serde_json::to_string_pretty(&claims).unwrap_or_default()
        );

        // Extract required claims
        let provider_id = Self::extract_subject(&claims)?;
        let user_email = Self::extract_email(&claims)
            .or_else(|| {
                // Fallback to Apple user info if email not in token
                if let Some(ref apple_info) = apple_user_info {
                    if let Some(ref email) = apple_info.email {
                        debug!("Using Apple user info email as fallback: {email}");
                        return Some(email.clone());
                    }
                }
                debug!("No email found in ID token or Apple user info, using default");
                Some("user@example.com".to_string())
            })
            .unwrap(); // This unwrap is safe because we provide a default

        // Extract optional claims
        let mut user_name = Self::extract_name(&claims);

        // Use Apple user info name as fallback if name not found in ID token
        if user_name.is_none() {
            if let Some(ref apple_info) = apple_user_info {
                let apple_name = format!(
                    "{} {}",
                    apple_info.name.first_name.as_deref().unwrap_or(""),
                    apple_info.name.last_name.as_deref().unwrap_or("")
                );
                if !apple_name.trim().is_empty() {
                    debug!("Using Apple user info name as fallback: {apple_name}");
                    user_name = Some(apple_name);
                }
            }
        }
        let created_at = Self::extract_issued_at(&claims);
        // let expires_at = Self::extract_expires_at(&claims);

        // Normalize provider name from issuer if available
        let normalized_provider = Self::normalize_provider(&provider, &claims);

        info!(
            "Session built successfully - Email: {user_email}, Provider: {normalized_provider}, Provider ID: {provider_id}, Name: {user_name:?}"
        );

        Ok(CompleteSessionData {
            user_email,
            user_name,
            provider: normalized_provider,
            provider_id,
            id_token: id_token.clone(),
            refresh_token,
            expires_at,
            created_at: created_at.unwrap_or_else(Utc::now),
        })
    }

    /// Extract the subject (sub) claim - maps to `provider_id`
    fn extract_subject(claims: &Value) -> Result<String, String> {
        claims
            .get("sub")
            .and_then(|v| v.as_str())
            .map(std::string::ToString::to_string)
            .ok_or_else(|| "Missing or invalid 'sub' claim in ID token".to_string())
    }

    /// Extract the email claim - maps to `user_email` (returns Option for fallback logic)
    #[must_use]
    pub fn extract_email(claims: &Value) -> Option<String> {
        claims
            .get("email")
            .and_then(|v| v.as_str())
            .map(std::string::ToString::to_string)
    }

    /// Extract the name claim - maps to `user_name` (optional)
    fn extract_name(claims: &Value) -> Option<String> {
        // Try different name claim formats used by different providers

        // Google uses 'name' field directly
        if let Some(name) = claims.get("name").and_then(|v| v.as_str()) {
            if !name.trim().is_empty() {
                debug!("Extracted name from 'name' claim: {name}");
                return Some(name.to_string());
            }
        }

        // Apple and others might use given_name + family_name
        let given_name = claims
            .get("given_name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let family_name = claims
            .get("family_name")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if !given_name.is_empty() || !family_name.is_empty() {
            let full_name = format!("{given_name} {family_name}").trim().to_string();
            if !full_name.is_empty() {
                debug!(
                    "Extracted name from given_name + family_name: {full_name}"
                );
                return Some(full_name);
            }
        }

        debug!("No name information found in ID token claims");
        None
    }

    /// Generic timestamp extraction helper
    fn extract_timestamp(claims: &Value, field_name: &str) -> Option<DateTime<Utc>> {
        claims
            .get(field_name)
            .and_then(serde_json::Value::as_i64)
            .and_then(|timestamp| if let chrono::LocalResult::Single(dt) = Utc.timestamp_opt(timestamp, 0) {
                debug!(
                    "Extracted {field_name} from '{field_name}' claim: {dt}"
                );
                Some(dt)
            } else {
                warn!(
                    "Invalid '{field_name}' timestamp in ID token: {timestamp}"
                );
                None
            })
    }

    /// Extract the issued at (iat) claim - maps to `created_at`
    fn extract_issued_at(claims: &Value) -> Option<DateTime<Utc>> {
        Self::extract_timestamp(claims, "iat")
    }

    /// Normalize provider name from issuer claim if available
    fn normalize_provider(provider: &str, claims: &Value) -> String {
        if let Some(issuer) = claims.get("iss").and_then(|v| v.as_str()) {
            debug!("Found issuer claim: {issuer}");

            // Map common issuer values to normalized provider names
            if issuer.contains("accounts.google.com") {
                return "google".to_string();
            } else if issuer.contains("appleid.apple.com") {
                return "apple".to_string();
            }
        }

        // Fall back to the provider passed in from the state
        provider.to_string()
    }

    /// Extract client information from the request
    fn extract_client_info(req: &actix_web::HttpRequest) -> (Option<String>, crate::utils::user_agent::UserAgentInfo) {
        use crate::utils::user_agent::extract_user_agent_info;
        
        let client_ip = req
            .connection_info()
            .realip_remote_addr()
            .map(std::string::ToString::to_string);
        
        let user_agent_info = extract_user_agent_info(req);
        
        (client_ip, user_agent_info)
    }
    
    /// Create error response for session building failures
    fn create_error_response(session_manager: &crate::session::SessionManager, error_msg: &str) -> actix_web::HttpResponse {
        use log::error;
        
        error!("{}", error_msg);
        let clear_cookie = session_manager.create_expired_cookie();
        actix_web::HttpResponse::Found()
            .cookie(clear_cookie)
            .append_header(("Location", "/oauth2/sign_in?error=session_build_error"))
            .finish()
    }

    /// Finalizes a session and creates an HTTP response with session cookies
    /// 
    /// This method encapsulates the complete session finalization process:
    /// 1. Builds the session from OAuth tokens
    /// 2. Creates session and user cookies
    /// 3. Validates redirect URL
    /// 4. Returns HttpResponse with all cookies
    /// 
    /// # Arguments
    /// 
    /// * `req` - HTTP request for extracting client info
    /// * `session_manager` - Session manager for cookie creation
    /// * `provider` - OAuth provider name
    /// * `id_token` - Optional ID token from OAuth provider
    /// * `refresh_token` - Optional refresh token from OAuth provider
    /// * `expires_at` - Token expiration time
    /// * `apple_user_info` - Optional Apple user info (for Apple Sign In)
    /// * `redirect_url` - Optional URL to redirect to after successful authentication
    pub fn finalize_session(
        req: &actix_web::HttpRequest,
        session_manager: &crate::session::SessionManager,
        auth_data: &AuthenticationData,
        redirect_url: Option<String>,
    ) -> actix_web::HttpResponse {
        use crate::utils::cookie::{create_expired_cookie, OAUTH_STATE_COOKIE};
        use crate::utils::redirect_validator::validate_post_auth_redirect;
        use crate::utils::response_builder::success_redirect_with_cookies;

        // Extract client info
        let (client_ip, user_agent_info) = Self::extract_client_info(req);

        // Build the session (without access token)
        let session_result = Self::build_session_with_apple_info(
            auth_data.provider.to_string(),
            auth_data.id_token.clone(),
            auth_data.refresh_token.clone(),
            auth_data.expires_at,
            auth_data.apple_user_info.clone(),
        );

        match session_result {
            Ok(complete_session) => {
                info!(
                    "Successfully built session for user: {} (provider: {})",
                    complete_session.user_email, auth_data.provider
                );

                // Split complete session into token data and user data
                let session = complete_session.to_session();
                let user_data =
                    complete_session.to_user_data(client_ip.as_deref(), Some(&user_agent_info));

                // Create both session and user cookies
                let session_cookie = match session_manager.create_session_cookie(&session) {
                    Ok(cookie) => cookie,
                    Err(e) => {
                        let error_msg = format!("Failed to create session cookie: {e}");
                        return Self::create_error_response(session_manager, &error_msg);
                    }
                };

                let user_cookie = match session_manager.create_user_cookie(&user_data) {
                    Ok(cookie) => cookie,
                    Err(e) => {
                        let error_msg = format!("Failed to create user cookie: {e}");
                        return Self::create_error_response(session_manager, &error_msg);
                    }
                };

                let clear_temp_cookie = create_expired_cookie(OAUTH_STATE_COOKIE, session_manager.cookie_secure());
                let redirect_to = redirect_url.unwrap_or_else(|| "/".to_string());

                // Validate the redirect URL to prevent open redirect attacks
                let validated_redirect = validate_post_auth_redirect(&redirect_to).unwrap_or_else(|_| {
                    log::error!("Invalid post-authentication redirect URL '{redirect_to}': rejecting");
                    // Fallback to safe default on validation failure
                    "/".to_string()
                });

                // Create response with multiple cookies
                success_redirect_with_cookies(
                    &validated_redirect,
                    vec![session_cookie, user_cookie, clear_temp_cookie],
                )
            }
            Err(e) => {
                let error_msg = format!("Failed to build session from ID token: {e}");
                Self::create_error_response(session_manager, &error_msg)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::apple::{AppleUserInfo, AppleUserName};
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
    fn test_apple_userinfo_copied_to_vouchrsession() {
        let id_token = Some(minimal_id_token("apple-sub-123"));
        let refresh_token = Some("refresh123".to_string());
        let expires_at = Utc::now() + chrono::Duration::hours(1);
        let apple_user_info = AppleUserInfo {
            name: AppleUserName {
                first_name: Some("Jane".to_string()),
                last_name: Some("Doe".to_string()),
            },
            email: Some("jane.doe@apple.com".to_string()),
        };
        // Test with AppleUserInfo as struct (Value::Object case)
        let session = SessionBuilder::build_session_with_apple_info(
            "apple".to_string(),
            id_token.clone(),
            refresh_token.clone(),
            expires_at,
            Some(apple_user_info.clone()),
        )
        .expect("Session should be built");
        assert_eq!(session.user_email, apple_user_info.email.clone().unwrap());
        assert_eq!(
            session.user_name.clone().unwrap(),
            format!(
                "{} {}",
                apple_user_info.name.first_name.as_deref().unwrap_or(""),
                apple_user_info.name.last_name.as_deref().unwrap_or("")
            )
        );
        assert_eq!(session.provider, "apple");
        assert_eq!(session.provider_id, "apple-sub-123");

        // Test that session building works correctly with Apple user info
        // The important part is that the Apple user info is properly incorporated into the session
        assert_eq!(session.user_email, "jane.doe@apple.com");
        assert_eq!(session.user_name.unwrap(), "Jane Doe");
    }

    #[test]
    fn test_extract_subject_success() {
        let claims = json!({
            "sub": "12345",
            "email": "test@example.com"
        });

        assert_eq!(SessionBuilder::extract_subject(&claims).unwrap(), "12345");
    }

    #[test]
    fn test_extract_subject_missing() {
        let claims = json!({
            "email": "test@example.com"
        });

        assert!(SessionBuilder::extract_subject(&claims).is_err());
    }

    #[test]
    fn test_extract_name_google_format() {
        let claims = json!({
            "name": "John Doe"
        });

        assert_eq!(
            SessionBuilder::extract_name(&claims),
            Some("John Doe".to_string())
        );
    }

    #[test]
    fn test_extract_name_apple_format() {
        let claims = json!({
            "given_name": "John",
            "family_name": "Doe"
        });

        assert_eq!(
            SessionBuilder::extract_name(&claims),
            Some("John Doe".to_string())
        );
    }

    #[test]
    fn test_extract_name_missing() {
        let claims = json!({
            "sub": "12345",
            "email": "test@example.com"
        });

        assert_eq!(SessionBuilder::extract_name(&claims), None);
    }
}
