//! Session Manager - Stateless Encrypted Session Handling
//!
//! This module provides the `SessionManager` which serves as the single source of truth
//! for session creation and management in Vouchrs. It delegates to specialized modules
//! for specific functionality while maintaining a clean, organized interface.
//!
//! ## Architecture
//!
//! The `SessionManager` follows a delegation pattern:
//! - **OAuth operations**: Delegates to `oauth` module utilities
//! - **Passkey operations**: Delegates to `passkey` module utilities
//! - **Validation logic**: Delegates to `validation` module functions
//! - **Cookie management**: Delegates to `CookieFactory` for all cookie operations
//!
//! ## Organization
//!
//! This file is organized into the following logical sections:
//!
//! 1. **Imports and Types** - External dependencies and type definitions
//! 2. **Construction** - `SessionManager` creation and configuration
//! 3. **Service Access** - OAuth and Passkey service management
//! 4. **Session Extraction** - Reading and decrypting sessions from requests
//! 5. **Security & Validation** - Session security checks and validation
//! 6. **Session Creation** - Creating sessions from authentication results
//! 7. **Response Creation** - Building HTTP responses with session cookies
//! 8. **Utilities** - Helper functions and accessors
//! 9. **Tests** - Unit tests for functionality verification

use crate::models::{VouchrsSession, VouchrsUserData};
use crate::oauth::OAuthState;
use crate::session::cookie::{CookieFactory, COOKIE_NAME, USER_COOKIE_NAME};
use crate::utils::crypto::{decrypt_data, derive_encryption_key};
use crate::utils::responses::ResponseBuilder;
use actix_web::{HttpRequest, HttpResponse, ResponseError};
use anyhow::{anyhow, Result};
use chrono::Utc;
use std::sync::Arc;

// =============================================================================
// Types and Error Handling
// =============================================================================

/// Response type enumeration for unified response creation
#[derive(Debug, Clone, Copy)]
pub enum ResponseType {
    /// HTML redirect response for browser requests
    Redirect,
    /// JSON response for AJAX/API requests
    Json,
}

/// Custom error wrapper for `ResponseError` implementation
#[derive(Debug)]
pub struct SessionError(anyhow::Error);

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<anyhow::Error> for SessionError {
    fn from(err: anyhow::Error) -> Self {
        Self(err)
    }
}

impl ResponseError for SessionError {
    fn error_response(&self) -> HttpResponse {
        let error_msg = self.0.to_string();

        if error_msg.contains("Session expired") || error_msg.contains("Session not found") {
            ResponseBuilder::unauthorized().build()
        } else {
            ResponseBuilder::internal_server_error().build()
        }
    }
}

// =============================================================================
// Session Manager Structure
// =============================================================================

/// Session Manager for stateless encrypted session handling
///
/// The `SessionManager` serves as the central coordination point for session operations
/// in Vouchrs, providing a clean interface while delegating to specialized modules.
#[derive(Clone)]
pub struct SessionManager {
    encryption_key: [u8; 32],
    cookie_secure: bool,
    bind_session_to_ip: bool,
    session_expiration_hours: u64,
    // Cookie factory for all cookie operations
    cookie_factory: CookieFactory,
    // Authentication services (optional - can be None if disabled)
    oauth_service: Option<Arc<dyn crate::oauth::OAuthAuthenticationService + Send + Sync>>,
    passkey_service: Option<Arc<dyn crate::passkey::PasskeyAuthenticationService + Send + Sync>>,
}

// =============================================================================
// 1. Construction
// =============================================================================

impl SessionManager {
    /// Create a new session manager with cookie refresh configuration
    #[must_use]
    pub fn new(
        key: &[u8],
        cookie_secure: bool,
        bind_session_to_ip: bool,
        session_duration_hours: u64,
        session_expiration_hours: u64,
        session_refresh_hours: u64,
    ) -> Self {
        let encryption_key = derive_encryption_key(key);

        let cookie_factory = CookieFactory::new(
            encryption_key,
            cookie_secure,
            session_duration_hours,
            session_refresh_hours,
            bind_session_to_ip,
        );

        Self {
            encryption_key,
            cookie_secure,
            bind_session_to_ip,
            session_expiration_hours,
            cookie_factory,
            oauth_service: None,
            passkey_service: None,
        }
    }
}

// =============================================================================
// 2. Service Access
// =============================================================================

impl SessionManager {
    /// Configure OAuth authentication service
    #[must_use]
    pub fn with_oauth_service(
        mut self,
        service: Arc<dyn crate::oauth::OAuthAuthenticationService + Send + Sync>,
    ) -> Self {
        self.oauth_service = Some(service);
        self
    }

    /// Configure Passkey authentication service
    #[must_use]
    pub fn with_passkey_service(
        mut self,
        service: Arc<dyn crate::passkey::PasskeyAuthenticationService + Send + Sync>,
    ) -> Self {
        self.passkey_service = Some(service);
        self
    }

    /// Get reference to OAuth service if available
    #[must_use]
    pub fn oauth_service(
        &self,
    ) -> Option<&(dyn crate::oauth::OAuthAuthenticationService + Send + Sync)> {
        self.oauth_service.as_ref().map(std::convert::AsRef::as_ref)
    }

    /// Get reference to Passkey service if available
    #[must_use]
    pub fn passkey_service(
        &self,
    ) -> Option<&(dyn crate::passkey::PasskeyAuthenticationService + Send + Sync)> {
        self.passkey_service
            .as_ref()
            .map(std::convert::AsRef::as_ref)
    }

    /// Check if OAuth service is available
    #[must_use]
    pub fn has_oauth_service(&self) -> bool {
        self.oauth_service.is_some()
    }

    /// Check if Passkey service is available
    #[must_use]
    pub fn has_passkey_service(&self) -> bool {
        self.passkey_service.is_some()
    }
}

// =============================================================================
// 3. Session Extraction
// =============================================================================

impl SessionManager {
    /// Extract session from HTTP request with full validation
    ///
    /// This is the primary method for session extraction, providing comprehensive
    /// validation including IP binding and expiration checks.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No session cookie is found
    /// - Session decryption fails
    /// - Session validation fails (expired, IP mismatch, etc.)
    pub fn extract_session(&self, req: &HttpRequest) -> Result<VouchrsSession> {
        let session = self
            .get_session_from_request(req)?
            .ok_or_else(|| anyhow!("No valid session found"))?;

        // Perform comprehensive session validation
        self.validate_session_comprehensive(&session, req)?;

        Ok(session)
    }

    /// Get session from HTTP request cookies with basic validation
    ///
    /// This method extracts and decrypts the session but performs minimal validation.
    /// Use `extract_session` for full validation.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption fails (expired sessions with refresh tokens are returned)
    pub fn get_session_from_request(&self, req: &HttpRequest) -> Result<Option<VouchrsSession>> {
        let cookie = req
            .cookie(COOKIE_NAME)
            .ok_or_else(|| anyhow!("No session cookie found"))?;

        let session = decrypt_data::<VouchrsSession>(cookie.value(), &self.encryption_key)?;

        Ok(self.process_decrypted_session(session, req))
    }

    /// Get OAuth state from temporary cookie in request
    ///
    /// # Errors
    ///
    /// Returns an error if decryption fails (other errors are logged and return None)
    pub fn get_temporary_state_from_request(
        &self,
        req: &HttpRequest,
    ) -> Result<Option<OAuthState>> {
        let cookie_name = crate::session::cookie::OAUTH_STATE_COOKIE;
        log::info!("Looking for temporary state cookie '{cookie_name}'");

        // Log all cookies in the request for debugging
        crate::session::cookie::log_cookies(req);

        req.cookie(cookie_name).map_or_else(
            || {
                log::warn!("No temporary state cookie '{cookie_name}' found in request");
                Ok(None)
            },
            |cookie| {
                log::info!(
                    "Found temporary state cookie with value length: {}",
                    cookie.value().len()
                );
                match decrypt_data::<OAuthState>(cookie.value(), &self.encryption_key) {
                    Ok(oauth_state) => Ok(Some(oauth_state)),
                    Err(e) => {
                        log::warn!("Failed to decrypt OAuth state cookie: {e}");
                        Ok(None)
                    }
                }
            },
        )
    }

    /// Extract user data from encrypted user cookie
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No user cookie is found
    /// - User data decryption fails
    /// - User data validation fails
    pub fn extract_user_data(&self, req: &HttpRequest) -> Result<VouchrsUserData> {
        let cookie = req
            .cookie(USER_COOKIE_NAME)
            .ok_or_else(|| anyhow!("No user cookie found"))?;

        let user_data = decrypt_data::<VouchrsUserData>(cookie.value(), &self.encryption_key)?;

        Ok(user_data)
    }

    /// Process a successfully decrypted session for validation and expiration handling
    fn process_decrypted_session(
        &self,
        session: VouchrsSession,
        req: &HttpRequest,
    ) -> Option<VouchrsSession> {
        // Check IP binding if enabled
        if self.bind_session_to_ip && !self.validate_session_ip_binding(&session, req) {
            log::warn!("Session IP validation failed - session rejected");
            return None;
        }

        // Handle session expiration
        Self::handle_session_expiration(session)
    }

    /// Handle session expiration logic
    fn handle_session_expiration(session: VouchrsSession) -> Option<VouchrsSession> {
        let now = Utc::now();

        if session.expires_at <= now {
            log::debug!(
                "Session expired at {}, current time: {}",
                session.expires_at,
                now
            );

            // Allow expired sessions with refresh tokens to be returned for token refresh
            if session.refresh_token.is_some() {
                log::debug!("Returning expired session with refresh token for potential renewal");
                Some(session)
            } else {
                log::debug!("Session expired without refresh token - rejecting");
                None
            }
        } else {
            Some(session)
        }
    }

    /// Legacy method for backward compatibility with existing code
    ///
    /// # Errors
    ///
    /// Returns an error if session decryption or validation fails
    pub fn decrypt_and_validate_session(&self, cookie_value: &str) -> Result<VouchrsSession> {
        decrypt_data::<VouchrsSession>(cookie_value, &self.encryption_key)
    }

    /// Legacy method for session decryption with IP context
    ///
    /// # Errors
    ///
    /// Returns an error if session decryption or IP validation fails
    pub fn decrypt_and_validate_session_with_ip(
        &self,
        cookie_value: &str,
        req: &HttpRequest,
    ) -> Result<VouchrsSession> {
        let session = decrypt_data::<VouchrsSession>(cookie_value, &self.encryption_key)?;

        if self.bind_session_to_ip && !self.validate_session_ip_binding(&session, req) {
            return Err(anyhow!("Session IP validation failed"));
        }

        Ok(session)
    }
}

// =============================================================================
// 4. Security & Validation
// =============================================================================

impl SessionManager {
    /// Validate session with comprehensive security checks
    ///
    /// Performs all security validations including IP binding, expiration,
    /// and client context validation. Delegates to validation module.
    ///
    /// # Errors
    ///
    /// Returns an error if any validation check fails
    pub fn validate_session_comprehensive(
        &self,
        session: &VouchrsSession,
        req: &HttpRequest,
    ) -> Result<()> {
        // IP binding validation (delegated to validation module)
        if self.bind_session_to_ip && !crate::session::validation::validate_ip_binding(session, req)
        {
            return Err(anyhow!("Session IP validation failed"));
        }

        // Check session expiration (delegated to validation module)
        if crate::session::validation::is_session_time_expired(session) {
            return Err(anyhow!("Session has expired"));
        }

        Ok(())
    }

    /// Validate client context using user data (delegates to validation module)
    ///
    /// # Errors
    ///
    /// Returns an error if client context validation fails
    pub fn validate_client_context_only(
        &self,
        user_data: &VouchrsUserData,
        req: &HttpRequest,
    ) -> Result<()> {
        if crate::session::validation::validate_client_context(user_data, req) {
            Ok(())
        } else {
            Err(anyhow!("Client context validation failed"))
        }
    }

    /// Validate session IP binding (delegates to validation module)
    #[must_use]
    pub fn validate_session_ip_binding(&self, session: &VouchrsSession, req: &HttpRequest) -> bool {
        if !self.bind_session_to_ip {
            return true;
        }
        crate::session::validation::validate_ip_binding(session, req)
    }

    /// Validate session for security (delegates to validation module)
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails
    pub fn validate_session_security(
        &self,
        user_data: &VouchrsUserData,
        req: &HttpRequest,
    ) -> Result<bool, &'static str> {
        crate::session::validation::validate_session_security(
            user_data,
            req,
            self.session_expiration_hours,
        )
    }

    /// Check if a session needs token refresh (delegates to validation module)
    ///
    /// This method checks if an OAuth session's tokens are close to expiration
    /// and should be refreshed.
    #[must_use]
    pub fn needs_token_refresh(&self, session: &VouchrsSession) -> bool {
        crate::session::validation::needs_token_refresh(session)
    }

    /// Check if session has expired (delegates to validation module)
    ///
    /// This method checks if user data indicates an expired session based on
    /// the configured session expiration hours.
    #[must_use]
    pub fn is_session_expired(&self, user_data: &VouchrsUserData) -> bool {
        crate::session::validation::is_session_expired(user_data, self.session_expiration_hours)
    }
}

// =============================================================================
// 5. Session Creation (UNIFIED ENTRY POINTS - No More Wrapper Chains)
// =============================================================================

impl SessionManager {
    /// Handle OAuth authentication flow (UNIFIED ENTRY POINT)
    ///
    /// This REPLACES the wrapper chain:
    /// `handle_oauth_callback()` → `create_session_from_oauth_result()` → `handle_oauth_callback_direct()`
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - OAuth service is not available
    /// - OAuth callback processing fails
    /// - Session creation fails
    pub async fn handle_oauth_callback(
        &self,
        req: &HttpRequest,
        provider: &str,
        authorization_code: &str,
        oauth_state: &crate::oauth::OAuthState,
        apple_user_info: Option<crate::utils::apple::AppleUserInfo>,
        response_type: ResponseType,
    ) -> Result<HttpResponse, HttpResponse> {
        let oauth_service = self
            .oauth_service
            .as_ref()
            .ok_or_else(|| Self::create_service_unavailable_response("OAuth"))?;

        // Call OAuth service to get OAuth result (no session creation)
        let oauth_result = oauth_service
            .process_oauth_callback(provider, authorization_code, oauth_state, apple_user_info)
            .await
            .map_err(|e| {
                log::error!("OAuth callback processing failed: {e}");
                Self::create_service_error_response("OAuth authentication failed")
            })?;

        // Create session directly from OAuth result
        let (session, user_data) = self.create_oauth_session(oauth_result, req).map_err(|e| {
            log::error!("Failed to create OAuth session: {e}");
            Self::create_service_error_response("Session creation failed")
        })?;

        // Create response with appropriate format
        self.create_session_response(
            req,
            &session,
            &user_data,
            oauth_state.redirect_url.clone(),
            response_type,
        )
    }

    /// Handle passkey registration (UNIFIED ENTRY POINT)
    ///
    /// This REPLACES `handle_passkey_registration()` and `handle_passkey_registration_json()`
    /// by using a `ResponseType` parameter.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Passkey service is not available
    /// - Registration processing fails
    /// - Session creation fails
    pub fn handle_passkey_registration(
        &self,
        req: &HttpRequest,
        registration_data: crate::passkey::PasskeyRegistrationData,
        response_type: ResponseType,
    ) -> Result<HttpResponse, HttpResponse> {
        let passkey_service = self
            .passkey_service
            .as_ref()
            .ok_or_else(|| Self::create_service_unavailable_response("Passkey"))?;

        let passkey_result = passkey_service
            .complete_registration(registration_data)
            .map_err(|e| {
                log::error!("Passkey registration failed: {e}");
                Self::create_service_error_response("Passkey registration failed")
            })?;

        // Create session directly from passkey result
        let (session, user_data) =
            self.create_passkey_session(passkey_result, req)
                .map_err(|e| {
                    log::error!("Failed to create passkey session: {e}");
                    Self::create_service_error_response("Session creation failed")
                })?;

        // Create response with appropriate format
        self.create_session_response(req, &session, &user_data, None, response_type)
    }

    /// Handle passkey authentication (UNIFIED ENTRY POINT)
    ///
    /// This REPLACES `handle_passkey_authentication()` and `handle_passkey_authentication_json()`
    /// by using a `ResponseType` parameter.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Passkey service is not available
    /// - Authentication processing fails
    /// - Session creation fails
    pub fn handle_passkey_authentication(
        &self,
        req: &HttpRequest,
        authentication_data: crate::passkey::PasskeyAuthenticationData,
        response_type: ResponseType,
    ) -> Result<HttpResponse, HttpResponse> {
        let passkey_service = self
            .passkey_service
            .as_ref()
            .ok_or_else(|| Self::create_service_unavailable_response("Passkey"))?;

        let passkey_result = passkey_service
            .complete_authentication(authentication_data)
            .map_err(|e| {
                log::error!("Passkey authentication failed: {e}");
                Self::create_service_error_response("Passkey authentication failed")
            })?;

        // Create session directly from passkey result
        let (session, user_data) =
            self.create_passkey_session(passkey_result, req)
                .map_err(|e| {
                    log::error!("Failed to create passkey session: {e}");
                    Self::create_service_error_response("Session creation failed")
                })?;

        // Create response with appropriate format
        self.create_session_response(req, &session, &user_data, None, response_type)
    }

    /// Create session objects directly from OAuth result
    ///
    /// This method bypasses the `AuthenticationResult` abstraction and creates
    /// session objects directly from OAuth authentication results.
    ///
    /// # Errors
    ///
    /// Returns a session creation error if the input is invalid
    pub fn create_oauth_session(
        &self,
        oauth_result: crate::oauth::OAuthResult,
        req: &HttpRequest,
    ) -> Result<
        (
            crate::models::VouchrsSession,
            crate::models::VouchrsUserData,
        ),
        anyhow::Error,
    > {
        let (client_ip, user_agent_info) = crate::session::utils::extract_client_info(req);

        let session = crate::models::VouchrsSession {
            // OAuth-specific fields
            id_token: oauth_result.id_token,
            refresh_token: oauth_result.refresh_token,

            // No Passkey fields
            credential_id: None,
            user_handle: None,

            // Common fields
            provider: oauth_result.provider.clone(),
            expires_at: oauth_result.expires_at,
            authenticated_at: oauth_result.authenticated_at,
            client_ip: if self.bind_session_to_ip {
                client_ip.clone()
            } else {
                None
            },
        };

        let user_data = crate::models::VouchrsUserData {
            email: oauth_result.email.unwrap_or_default(),
            name: oauth_result.name,
            provider: oauth_result.provider,
            provider_id: oauth_result.provider_id,
            client_ip,
            user_agent: user_agent_info.user_agent,
            platform: user_agent_info.platform,
            lang: user_agent_info.lang,
            mobile: i32::from(user_agent_info.mobile),
            session_start: Some(oauth_result.authenticated_at.timestamp()),
        };

        Ok((session, user_data))
    }

    /// Create session objects directly from Passkey result
    ///
    /// This method bypasses the `AuthenticationResult` abstraction and creates
    /// session objects directly from Passkey authentication results.
    ///
    /// # Errors
    ///
    /// Returns a session creation error if the input is invalid
    pub fn create_passkey_session(
        &self,
        passkey_result: crate::passkey::PasskeyResult,
        req: &HttpRequest,
    ) -> Result<
        (
            crate::models::VouchrsSession,
            crate::models::VouchrsUserData,
        ),
        anyhow::Error,
    > {
        let (client_ip, user_agent_info) = crate::session::utils::extract_client_info(req);

        let session = crate::models::VouchrsSession {
            // No OAuth fields
            id_token: None,
            refresh_token: None,

            // Passkey-specific fields
            credential_id: Some(passkey_result.credential_id),
            user_handle: Some(passkey_result.user_handle),

            // Common fields
            provider: passkey_result.provider.clone(),
            expires_at: passkey_result.expires_at,
            authenticated_at: passkey_result.authenticated_at,
            client_ip: if self.bind_session_to_ip {
                client_ip.clone()
            } else {
                None
            },
        };

        let user_data = crate::models::VouchrsUserData {
            email: passkey_result.email.unwrap_or_default(),
            name: passkey_result.name,
            provider: passkey_result.provider,
            provider_id: passkey_result.provider_id,
            client_ip,
            user_agent: user_agent_info.user_agent,
            platform: user_agent_info.platform,
            lang: user_agent_info.lang,
            mobile: i32::from(user_agent_info.mobile),
            session_start: Some(passkey_result.authenticated_at.timestamp()),
        };

        Ok((session, user_data))
    }
}

// =============================================================================
// 6. Response Creation (UNIFIED - No More Duplication)
// =============================================================================

impl SessionManager {
    /// Create session response with unified response type handling
    ///
    /// This REPLACES the duplicate `create_session_response()` and `create_json_session_response()`
    /// methods with a single unified method using `ResponseType` enum.
    ///
    /// # Errors
    ///
    /// Returns an error if session cookie creation fails
    fn create_session_response(
        &self,
        req: &HttpRequest,
        session: &VouchrsSession,
        user_data: &VouchrsUserData,
        redirect_url: Option<String>,
        response_type: ResponseType,
    ) -> Result<HttpResponse, HttpResponse> {
        // Create session cookies - use IP binding if enabled
        let session_cookie = if self.bind_session_to_ip {
            self.cookie_factory
                .create_session_cookie_with_context(session, req)
        } else {
            self.cookie_factory.create_session_cookie(session)
        }
        .map_err(|e| {
            log::error!("Failed to create session cookie: {e}");
            Self::create_service_error_response("Session creation failed")
        })?;

        let user_cookie = self
            .cookie_factory
            .create_user_cookie_with_persistence(req, user_data)
            .map_err(|e| {
                log::error!("Failed to create user cookie: {e}");
                Self::create_service_error_response("Session creation failed")
            })?;

        // Create response based on type
        match response_type {
            ResponseType::Redirect => {
                let final_redirect_url = redirect_url.unwrap_or_else(|| "/".to_string());
                Ok(HttpResponse::Found()
                    .insert_header(("Location", final_redirect_url))
                    .cookie(session_cookie)
                    .cookie(user_cookie)
                    .finish())
            }
            ResponseType::Json => {
                let final_redirect_url = redirect_url.unwrap_or_else(|| "/".to_string());
                Ok(HttpResponse::Ok()
                    .cookie(session_cookie)
                    .cookie(user_cookie)
                    .json(serde_json::json!({
                        "success": true,
                        "message": "Authentication successful",
                        "redirect_url": final_redirect_url
                    })))
            }
        }
    }

    /// Create service unavailable response
    fn create_service_unavailable_response(service_name: &str) -> HttpResponse {
        log::error!("{service_name} service not available");
        ResponseBuilder::service_unavailable()
            .with_message(&format!("{service_name} authentication is not enabled"))
            .build()
    }

    /// Create service error response
    fn create_service_error_response(message: &str) -> HttpResponse {
        ResponseBuilder::internal_server_error()
            .with_message(message)
            .build()
    }
}

// =============================================================================
// 7. Utilities
// =============================================================================

impl SessionManager {
    /// Get reference to encryption key for direct use with crypto utils
    #[must_use]
    pub fn encryption_key(&self) -> &[u8] {
        &self.encryption_key
    }

    /// Get reference to cookie factory for direct cookie operations
    ///
    /// Use this when you need direct access to cookie creation methods
    /// or want to avoid the convenience wrapper methods in `SessionManager`.
    /// This provides access to all cookie factory functionality without
    /// the additional session management context.
    #[must_use]
    pub const fn cookie_factory(&self) -> &CookieFactory {
        &self.cookie_factory
    }

    /// Check if cookies should be marked as secure
    #[must_use]
    pub const fn cookie_secure(&self) -> bool {
        self.cookie_secure
    }

    /// Check if cookie refresh is enabled
    #[must_use]
    pub fn is_cookie_refresh_enabled(&self) -> bool {
        self.cookie_factory.is_cookie_refresh_enabled()
    }

    /// Check if session IP binding is enabled
    #[must_use]
    pub const fn is_session_ip_binding_enabled(&self) -> bool {
        self.bind_session_to_ip
    }
}

// =============================================================================
// 8. Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::RequestBuilder;

    const TEST_JWT_KEY: &[u8] = b"test_jwt_secret_key_32_chars_min";

    #[test]
    fn test_session_manager_creation() {
        let manager = SessionManager::new(TEST_JWT_KEY, true, false, 24, 168, 1);

        assert!(manager.cookie_secure());
        assert!(!manager.is_session_ip_binding_enabled());
        assert!(!manager.has_oauth_service());
        assert!(!manager.has_passkey_service());
    }

    #[test]
    fn test_service_configuration() {
        let manager = SessionManager::new(TEST_JWT_KEY, false, false, 24, 168, 1);

        assert!(!manager.has_oauth_service());
        assert!(!manager.has_passkey_service());
        assert!(manager.oauth_service().is_none());
        assert!(manager.passkey_service().is_none());
    }

    #[test]
    fn test_response_type_enum() {
        // Test that ResponseType enum works correctly
        let redirect_type = ResponseType::Redirect;
        let json_type = ResponseType::Json;

        match redirect_type {
            ResponseType::Redirect => {}
            ResponseType::Json => panic!("Expected Redirect"),
        }

        match json_type {
            ResponseType::Json => {}
            ResponseType::Redirect => panic!("Expected Json"),
        }
    }

    #[test]
    fn test_session_extraction_without_cookie() {
        let manager = SessionManager::new(TEST_JWT_KEY, false, false, 24, 168, 1);
        let req = RequestBuilder::new().build();

        let result = manager.extract_session(&req);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No session cookie found"));
    }

    #[test]
    fn test_ip_binding_validation() {
        let manager_with_binding = SessionManager::new(
            TEST_JWT_KEY,
            false,
            true, // bind_session_to_ip = true
            24,
            168,
            1,
        );

        let manager_without_binding = SessionManager::new(
            TEST_JWT_KEY,
            false,
            false, // bind_session_to_ip = false
            24,
            168,
            1,
        );

        assert!(manager_with_binding.is_session_ip_binding_enabled());
        assert!(!manager_without_binding.is_session_ip_binding_enabled());
    }

    #[test]
    fn test_cookie_factory_access() {
        let manager = SessionManager::new(TEST_JWT_KEY, true, false, 24, 168, 1);

        let _factory = manager.cookie_factory();
        // Test that we can access the factory - the secure flag is stored in SessionManager
        assert!(manager.cookie_secure());
    }

    #[test]
    fn test_encryption_key_access() {
        let manager = SessionManager::new(TEST_JWT_KEY, false, false, 24, 168, 1);

        let key = manager.encryption_key();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_validation_comprehensive() {
        let manager = SessionManager::new(TEST_JWT_KEY, false, false, 24, 168, 1);
        let req = RequestBuilder::new().build();

        // Create a valid session (not expired)
        let session = VouchrsSession {
            id_token: None,
            refresh_token: None,
            credential_id: None,
            user_handle: None,
            provider: "test".to_string(),
            expires_at: Utc::now() + chrono::Duration::hours(1), // Valid for 1 hour
            authenticated_at: Utc::now(),
            client_ip: None,
        };

        // Should pass validation
        let result = manager.validate_session_comprehensive(&session, &req);
        assert!(result.is_ok());
    }

    #[test]
    fn test_expired_session_validation() {
        let manager = SessionManager::new(TEST_JWT_KEY, false, false, 24, 168, 1);
        let req = RequestBuilder::new().build();

        // Create an expired session
        let session = VouchrsSession {
            id_token: None,
            refresh_token: None,
            credential_id: None,
            user_handle: None,
            provider: "test".to_string(),
            expires_at: Utc::now() - chrono::Duration::hours(1), // Expired 1 hour ago
            authenticated_at: Utc::now() - chrono::Duration::hours(2),
            client_ip: None,
        };

        // Should fail validation
        let result = manager.validate_session_comprehensive(&session, &req);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[test]
    fn test_service_unavailable_responses() {
        let response = SessionManager::create_service_unavailable_response("OAuth");
        assert_eq!(
            response.status(),
            actix_web::http::StatusCode::SERVICE_UNAVAILABLE
        );

        let response = SessionManager::create_service_unavailable_response("Passkey");
        assert_eq!(
            response.status(),
            actix_web::http::StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn test_service_error_response() {
        let response = SessionManager::create_service_error_response("Test error");
        assert_eq!(
            response.status(),
            actix_web::http::StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
