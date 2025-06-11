use crate::models::{VouchrsSession, VouchrsUserData};
use crate::oauth::OAuthState;
use crate::session::cookie::{CookieOptions, COOKIE_NAME, USER_COOKIE_NAME};
use crate::session::validation::{calculate_client_context_hash, validate_client_context};
use crate::utils::crypto::{decrypt_data, derive_encryption_key, encrypt_data};
use crate::utils::responses::ResponseBuilder;
use actix_web::{cookie::Cookie, HttpRequest, HttpResponse, ResponseError};
use anyhow::{anyhow, Result};
use chrono::Utc;
use serde::Serialize;
use std::sync::Arc;

// Custom error wrapper for ResponseError implementation
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

/// Session Manager for stateless encrypted session handling
#[derive(Clone)]
pub struct SessionManager {
    encryption_key: [u8; 32],
    cookie_secure: bool,
    bind_session_to_ip: bool,
    session_duration_hours: u64,
    session_expiration_hours: u64,
    session_refresh_hours: u64,
    // Authentication services (optional - can be None if disabled)
    oauth_service: Option<Arc<dyn crate::oauth::OAuthAuthenticationService + Send + Sync>>,
    passkey_service: Option<Arc<dyn crate::passkey::PasskeyAuthenticationService + Send + Sync>>,
}

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

        Self {
            encryption_key,
            cookie_secure,
            bind_session_to_ip,
            session_duration_hours,
            session_expiration_hours,
            session_refresh_hours,
            oauth_service: None,
            passkey_service: None,
        }
    }

    /// Get reference to encryption key for direct use with crypto utils
    #[must_use]
    pub fn encryption_key(&self) -> &[u8] {
        &self.encryption_key
    }

    /// Create an encrypted session cookie from `VouchrsSession`
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails
    pub fn create_session_cookie(&self, session: &VouchrsSession) -> Result<Cookie> {
        self.create_cookie(
            COOKIE_NAME.to_string(),
            Some(session),
            CookieOptions {
                same_site: actix_web::cookie::SameSite::Lax,
                max_age: actix_web::cookie::time::Duration::hours(
                    i64::try_from(self.session_duration_hours).unwrap_or(24),
                ),
                ..Default::default()
            },
        )
    }

    /// Extract and decrypt session from HTTP request
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Session cookie is not found
    /// - Decryption fails
    /// - Session has expired AND no refresh token is available
    /// - IP binding validation fails
    pub fn extract_session(&self, req: &HttpRequest) -> Result<VouchrsSession> {
        let cookie_value = req
            .cookie(COOKIE_NAME)
            .ok_or_else(|| anyhow!("Session not found"))?
            .value()
            .to_string();

        let session: VouchrsSession = decrypt_data(&cookie_value, &self.encryption_key)?;

        // Validate IP binding if enabled
        if !self.validate_session_ip_binding(&session, req) {
            return Err(anyhow!("Session IP validation failed"));
        }

        // Check if tokens are expired
        if session.expires_at <= Utc::now() {
            // If session is expired but has a refresh token, allow it through for token refresh
            if session.refresh_token.is_some() {
                log::info!("Session is expired but has refresh token - allowing for token refresh");
                return Ok(session);
            }
            return Err(anyhow!("Session expired and no refresh token available"));
        }

        Ok(session)
    }

    /// Check if session needs token refresh (within 5 minutes of expiry)
    #[must_use]
    pub fn needs_token_refresh(&self, session: &VouchrsSession) -> bool {
        let now = Utc::now();
        let buffer_time = chrono::Duration::minutes(5);
        session.expires_at <= now + buffer_time
    }

    /// Get the cookie secure setting
    #[must_use]
    pub const fn cookie_secure(&self) -> bool {
        self.cookie_secure
    }

    /// Check if cookie refresh is enabled
    #[must_use]
    pub fn is_cookie_refresh_enabled(&self) -> bool {
        self.session_refresh_hours > 0
    }

    /// Check if session IP binding is enabled
    #[must_use]
    pub const fn is_session_ip_binding_enabled(&self) -> bool {
        self.bind_session_to_ip
    }

    /// Create a refreshed session cookie with extended expiration
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails
    pub fn create_refreshed_session_cookie(&self, session: &VouchrsSession) -> Result<Cookie> {
        if !self.is_cookie_refresh_enabled() {
            return self.create_session_cookie(session);
        }

        // Create cookie with refresh interval (already in hours)
        let refresh_duration = i64::try_from(self.session_refresh_hours).unwrap_or(1);

        self.create_cookie(
            COOKIE_NAME.to_string(),
            Some(session),
            CookieOptions {
                same_site: actix_web::cookie::SameSite::Lax,
                max_age: actix_web::cookie::time::Duration::hours(refresh_duration),
                ..Default::default()
            },
        )
    }

    /// Create an expired cookie to clear the session
    #[must_use]
    pub fn create_expired_cookie(&self) -> Cookie<'static> {
        crate::session::cookie::create_expired_cookie(COOKIE_NAME, self.cookie_secure)
    }

    /// Create a temporary cookie for storing OAuth state during the OAuth flow
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails
    pub fn create_temporary_state_cookie(
        &self,
        oauth_state: &OAuthState,
    ) -> Result<Cookie<'static>> {
        let cookie_name = crate::session::cookie::OAUTH_STATE_COOKIE;
        let options = CookieOptions {
            same_site: actix_web::cookie::SameSite::Lax,
            max_age: actix_web::cookie::time::Duration::minutes(10), // Short-lived for OAuth flow
            ..Default::default()
        };

        let cookie = self.create_cookie(cookie_name.to_string(), Some(oauth_state), options)?;

        log::info!(
            "Creating temporary state cookie: secure={}, name={}, encrypted_len={}",
            self.cookie_secure,
            cookie_name,
            cookie.value().len()
        );

        Ok(cookie)
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

    /// Get session from HTTP request cookies
    ///
    /// # Errors
    ///
    /// Returns an error if decryption fails (expired sessions with refresh tokens are returned)
    pub fn get_session_from_request(&self, req: &HttpRequest) -> Result<Option<VouchrsSession>> {
        let Some(cookie) = req.cookie(COOKIE_NAME) else {
            return Ok(None);
        };

        match decrypt_data::<VouchrsSession>(cookie.value(), &self.encryption_key) {
            Ok(session) => Ok(self.process_decrypted_session(session, req)),
            Err(e) if e.to_string().contains("Session expired") => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Process a successfully decrypted session for validation and expiration handling
    fn process_decrypted_session(
        &self,
        session: VouchrsSession,
        req: &HttpRequest,
    ) -> Option<VouchrsSession> {
        // Validate IP binding if enabled
        if !self.validate_session_ip_binding(&session, req) {
            log::warn!("Session IP validation failed during extraction");
            return None;
        }

        self.handle_session_expiration(session)
    }

    /// Handle session expiration logic and refresh token availability
    fn handle_session_expiration(&self, session: VouchrsSession) -> Option<VouchrsSession> {
        let now = Utc::now();

        // Check if session has expired
        if session.expires_at <= now {
            return if session.refresh_token.is_some() {
                log::info!(
                    "Session is expired but has refresh token - returning for token refresh"
                );
                Some(session)
            } else {
                None
            };
        }

        // Check if session needs token refresh using existing method
        if self.needs_token_refresh(&session) {
            log::warn!(
                "OAuth token needs refresh for provider: {}",
                session.provider
            );
        }

        Some(session)
    }

    /// Decrypt and validate session from cookie value
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Decryption fails
    /// - Session has expired AND no refresh token is available
    pub fn decrypt_and_validate_session(&self, cookie_value: &str) -> Result<VouchrsSession> {
        let session: VouchrsSession = decrypt_data(cookie_value, &self.encryption_key)?;

        // Check if session has expired
        if session.expires_at <= Utc::now() {
            // If session is expired but has a refresh token, allow it through for token refresh
            if session.refresh_token.is_some() {
                log::info!("Session is expired but has refresh token - allowing for token refresh");
                return Ok(session);
            }
            return Err(anyhow!("Session expired and no refresh token available"));
        }

        Ok(session)
    }

    /// Decrypt and validate session from cookie value with IP binding validation
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Decryption fails
    /// - Session has expired AND no refresh token is available
    /// - IP binding validation fails
    pub fn decrypt_and_validate_session_with_ip(
        &self,
        cookie_value: &str,
        req: &HttpRequest,
    ) -> Result<VouchrsSession> {
        let session: VouchrsSession = decrypt_data(cookie_value, &self.encryption_key)?;

        // Validate IP binding if enabled
        if !self.validate_session_ip_binding(&session, req) {
            return Err(anyhow!("Session IP validation failed"));
        }

        // Check if session has expired
        if session.expires_at <= Utc::now() {
            // If session is expired but has a refresh token, allow it through for token refresh
            if session.refresh_token.is_some() {
                log::info!("Session is expired but has refresh token - allowing for token refresh");
                return Ok(session);
            }
            return Err(anyhow!("Session expired and no refresh token available"));
        }

        Ok(session)
    }

    /// Create an encrypted user data cookie from `VouchrsUserData`
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails
    pub fn create_user_cookie(&self, user_data: &VouchrsUserData) -> Result<Cookie> {
        self.create_cookie(
            USER_COOKIE_NAME.to_string(),
            Some(user_data),
            CookieOptions {
                same_site: actix_web::cookie::SameSite::Lax,
                max_age: actix_web::cookie::time::Duration::hours(
                    i64::try_from(self.session_duration_hours).unwrap_or(24),
                ),
                ..Default::default()
            },
        )
    }

    /// Create an encrypted user data cookie with persistence across sessions
    ///
    /// This method checks for an existing user cookie with the same `provider_id`.
    /// If found and the existing cookie has populated `email` and `name` fields
    /// but the incoming request has null/empty values for these fields,
    /// it preserves the values from the existing cookie.
    ///
    /// # Arguments
    /// * `req` - The HTTP request to check for existing cookies
    /// * `user_data` - The new user data to store
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails
    pub fn create_user_cookie_with_persistence(
        &self,
        req: &HttpRequest,
        user_data: &VouchrsUserData,
    ) -> Result<Cookie> {
        // Check for existing user data with the same provider and provider_id
        if let Ok(Some(existing_user_data)) = self.get_user_data_from_request(req) {
            if existing_user_data.provider == user_data.provider
                && existing_user_data.provider_id == user_data.provider_id
            {
                // Create merged user data, preserving non-empty existing values
                let merged_user_data = Self::merge_user_data(&existing_user_data, user_data);

                log::info!(
                    "Persisting user data across sessions for provider '{}' with provider_id '{}': email preserved={}, name preserved={}",
                    user_data.provider,
                    user_data.provider_id,
                    merged_user_data.email != user_data.email,
                    merged_user_data.name != user_data.name
                );

                return self.create_user_cookie(&merged_user_data);
            }
        }

        // No existing data found or provider/provider_id doesn't match, create new cookie
        log::debug!(
            "Creating new user cookie for provider_id '{}' (no existing data to persist)",
            user_data.provider_id
        );
        self.create_user_cookie(user_data)
    }
    /// Merge user data, preserving existing non-empty email and name values
    /// when the new data has empty values
    fn merge_user_data(existing: &VouchrsUserData, new: &VouchrsUserData) -> VouchrsUserData {
        let mut merged = new.clone();

        // Preserve existing email if new email is empty and existing is not
        if new.email.is_empty() && !existing.email.is_empty() {
            merged.email.clone_from(&existing.email);
        }

        // Preserve existing name if new name is None and existing has a value
        if new.name.is_none() && existing.name.is_some() {
            merged.name.clone_from(&existing.name);
        }

        merged
    }

    /// Extract user data from HTTP request cookie
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - User data cookie is not found
    /// - Decryption fails
    pub fn extract_user_data(&self, req: &HttpRequest) -> Result<VouchrsUserData> {
        let cookie_value = req
            .cookie(USER_COOKIE_NAME)
            .ok_or_else(|| anyhow!("User data not found"))?
            .value()
            .to_string();

        decrypt_data(&cookie_value, &self.encryption_key)
    }

    /// Get user data from HTTP request cookies (returns None if not found)
    ///
    /// # Errors
    ///
    /// Returns an error if a critical failure occurs (decryption failures return None)
    pub fn get_user_data_from_request(&self, req: &HttpRequest) -> Result<Option<VouchrsUserData>> {
        req.cookie(USER_COOKIE_NAME).map_or_else(
            || Ok(None),
            |cookie| match decrypt_data::<VouchrsUserData>(cookie.value(), &self.encryption_key) {
                Ok(user_data) => Ok(Some(user_data)),
                Err(e) => {
                    log::warn!("Failed to decrypt user data cookie: {e}");
                    Ok(None)
                }
            },
        )
    }

    /// Validate client context against stored user data for session hijacking prevention
    ///
    /// # Arguments
    /// * `user_data` - The stored user data containing original client context
    /// * `req` - The current HTTP request to validate against
    ///
    /// Returns true if the client context matches (regardless of session expiration)
    #[must_use]
    pub fn validate_client_context_only(
        &self,
        user_data: &VouchrsUserData,
        req: &HttpRequest,
    ) -> bool {
        validate_client_context(user_data, req)
    }

    /// Check if session has expired based on session start time
    ///
    /// # Arguments
    /// * `user_data` - The stored user data containing session start timestamp
    ///
    /// Returns true if the session has expired
    #[must_use]
    pub fn is_session_expired(&self, user_data: &VouchrsUserData) -> bool {
        if let Some(session_start_timestamp) = user_data.session_start {
            let Some(session_start) = chrono::DateTime::from_timestamp(session_start_timestamp, 0)
            else {
                log::warn!("Invalid session start timestamp: {session_start_timestamp}");
                return true; // Treat invalid timestamps as expired
            };

            let session_age = Utc::now().signed_duration_since(session_start);
            let max_session_age =
                chrono::Duration::hours(i64::try_from(self.session_expiration_hours).unwrap_or(1));

            session_age > max_session_age
        } else {
            false // No session start time means session doesn't expire
        }
    }

    /// Validate session for security (client context + expiration awareness)
    ///
    /// **IMPORTANT**: This method should only be used for sensitive operations that require
    /// session hijacking protection (e.g., passkey registration, account changes).
    /// For regular proxy requests, use `decrypt_and_validate_session` instead.
    ///
    /// # Arguments
    /// * `user_data` - The stored user data containing original client context
    /// * `req` - The current HTTP request to validate against
    ///
    /// # Errors
    ///
    /// Returns an error if client context validation fails (session hijacking)
    ///
    /// Returns a result indicating the session status:
    /// - Ok(true) = Valid and not expired
    /// - Ok(false) = Valid but expired (can be refreshed)
    /// - Err(_) = Invalid due to hijacking
    pub fn validate_session_security(
        &self,
        user_data: &VouchrsUserData,
        req: &HttpRequest,
    ) -> Result<bool, &'static str> {
        // First validate client context for hijacking prevention
        if !self.validate_client_context_only(user_data, req) {
            return Err("Client context validation failed");
        }

        // Then check expiration status (but don't fail on expiration)
        let is_expired = self.is_session_expired(user_data);
        if is_expired {
            log::info!(
                "Session is expired but client context is valid - allowing for potential refresh"
            );
        }

        Ok(!is_expired)
    }

    /// Calculate client context hash for session hijacking prevention
    #[must_use]
    pub fn calculate_client_context_hash(
        &self,
        client_ip: Option<&str>,
        user_agent: Option<&str>,
        platform: Option<&str>,
    ) -> String {
        calculate_client_context_hash(client_ip, user_agent, platform)
    }

    /// Builder pattern for configuring OAuth service
    #[must_use]
    pub fn with_oauth_service(
        mut self,
        service: Arc<dyn crate::oauth::OAuthAuthenticationService + Send + Sync>,
    ) -> Self {
        self.oauth_service = Some(service);
        self
    }

    /// Builder pattern for configuring Passkey service
    #[must_use]
    pub fn with_passkey_service(
        mut self,
        service: Arc<dyn crate::passkey::PasskeyAuthenticationService + Send + Sync>,
    ) -> Self {
        self.passkey_service = Some(service);
        self
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

    /// Handle OAuth authentication flow
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
    ) -> Result<HttpResponse, HttpResponse> {
        if let Some(ref oauth_service) = self.oauth_service {
            // Extract client information from the request
            let (client_ip, user_agent_info) = crate::session::utils::extract_client_info(req);

            // Use the context-aware OAuth service method
            let result = oauth_service
                .process_oauth_callback(
                    provider,
                    authorization_code,
                    oauth_state,
                    apple_user_info,
                    client_ip.as_deref(),
                    Some(&user_agent_info),
                )
                .await
                .map_err(|e| {
                    log::error!("OAuth callback processing failed: {e}");
                    Self::create_service_error_response("OAuth authentication failed")
                })?;

            self.create_session_response(
                req,
                &result.session,
                &result.user_data,
                result.redirect_url,
            )
        } else {
            Err(Self::create_service_unavailable_response("OAuth"))
        }
    }

    /// Handle passkey registration
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
    ) -> Result<HttpResponse, HttpResponse> {
        if let Some(ref passkey_service) = self.passkey_service {
            let result = passkey_service
                .complete_registration(req, registration_data)
                .map_err(|e| {
                    log::error!("Passkey registration failed: {e}");
                    Self::create_service_error_response("Passkey registration failed")
                })?;

            self.create_session_response(
                req,
                &result.session,
                &result.user_data,
                result.redirect_url,
            )
        } else {
            Err(Self::create_service_unavailable_response("Passkey"))
        }
    }

    /// Handle passkey registration with JSON response
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Passkey service is not available
    /// - Registration processing fails
    /// - Session creation fails
    pub fn handle_passkey_registration_json(
        &self,
        req: &HttpRequest,
        registration_data: crate::passkey::PasskeyRegistrationData,
    ) -> Result<HttpResponse, HttpResponse> {
        if let Some(ref passkey_service) = self.passkey_service {
            let result = passkey_service
                .complete_registration(req, registration_data)
                .map_err(|e| {
                    log::error!("Passkey registration failed: {e}");
                    Self::create_service_error_response("Passkey registration failed")
                })?;

            self.create_json_session_response(
                req,
                &result.session,
                &result.user_data,
                result.redirect_url,
            )
        } else {
            Err(Self::create_service_unavailable_response("Passkey"))
        }
    }

    /// Handle passkey authentication
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
    ) -> Result<HttpResponse, HttpResponse> {
        if let Some(ref passkey_service) = self.passkey_service {
            let result = passkey_service
                .complete_authentication(req, authentication_data)
                .map_err(|e| {
                    log::error!("Passkey authentication failed: {e}");
                    Self::create_service_error_response("Passkey authentication failed")
                })?;

            self.create_session_response(
                req,
                &result.session,
                &result.user_data,
                result.redirect_url,
            )
        } else {
            Err(Self::create_service_unavailable_response("Passkey"))
        }
    }

    /// Handle passkey authentication with JSON response
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Passkey service is not available
    /// - Authentication processing fails
    /// - Session creation fails
    pub fn handle_passkey_authentication_json(
        &self,
        req: &HttpRequest,
        authentication_data: crate::passkey::PasskeyAuthenticationData,
    ) -> Result<HttpResponse, HttpResponse> {
        if let Some(ref passkey_service) = self.passkey_service {
            let result = passkey_service
                .complete_authentication(req, authentication_data)
                .map_err(|e| {
                    log::error!("Passkey authentication failed: {e}");
                    Self::create_service_error_response("Passkey authentication failed")
                })?;

            self.create_json_session_response(
                req,
                &result.session,
                &result.user_data,
                result.redirect_url,
            )
        } else {
            Err(Self::create_service_unavailable_response("Passkey"))
        }
    }

    // =============================================================================
    // Unified Authentication Methods using AuthenticationResult
    // =============================================================================

    /// Handle authentication using the unified `AuthenticationResult` type
    ///
    /// This method provides a unified interface for handling authentication results
    /// from any authentication service (OAuth, Passkey, etc.)
    ///
    /// # Errors
    ///
    /// Returns an error if session cookie creation fails
    pub fn handle_authentication_result(
        &self,
        req: &HttpRequest,
        auth_result: crate::models::auth::AuthenticationResult,
    ) -> Result<HttpResponse, HttpResponse> {
        self.create_session_response(
            req,
            &auth_result.session,
            &auth_result.user_data,
            auth_result.redirect_url,
        )
    }

    /// Handle authentication using the unified `AuthenticationResult` type with JSON response
    ///
    /// This method provides a unified interface for handling authentication results
    /// from any authentication service (OAuth, Passkey, etc.) with JSON response
    ///
    /// # Errors
    ///
    /// Returns an error if session cookie creation fails
    pub fn handle_authentication_result_json(
        &self,
        req: &HttpRequest,
        auth_result: crate::models::auth::AuthenticationResult,
    ) -> Result<HttpResponse, HttpResponse> {
        self.create_json_session_response(
            req,
            &auth_result.session,
            &auth_result.user_data,
            auth_result.redirect_url,
        )
    }

    /// Create session response from authentication result with cookies
    ///
    /// This method handles the conversion of authentication results to HTTP responses
    /// with appropriate session cookies and redirects
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
    ) -> Result<HttpResponse, HttpResponse> {
        // Create session cookies - use IP binding if enabled
        let session_cookie = if self.bind_session_to_ip {
            self.create_session_cookie_with_context(session, req)
        } else {
            self.create_session_cookie(session)
        }
        .map_err(|e| {
            log::error!("Failed to create session cookie: {e}");
            Self::create_service_error_response("Session creation failed")
        })?;

        let user_cookie = self
            .create_user_cookie_with_persistence(req, user_data)
            .map_err(|e| {
                log::error!("Failed to create user cookie: {e}");
                Self::create_service_error_response("Session creation failed")
            })?;

        // Handle redirect and create response
        let final_redirect_url = redirect_url.unwrap_or_else(|| "/".to_string());

        // Create response directly to avoid lifetime issues
        let mut response_builder = HttpResponse::Found();
        response_builder.append_header(("Location", final_redirect_url));
        response_builder.cookie(session_cookie);
        response_builder.cookie(user_cookie);

        Ok(response_builder.finish())
    }

    /// Create JSON session response for AJAX endpoints
    ///
    /// # Errors
    ///
    /// Returns an error if session cookie creation fails
    fn create_json_session_response(
        &self,
        req: &HttpRequest,
        session: &VouchrsSession,
        user_data: &VouchrsUserData,
        redirect_url: Option<String>,
    ) -> Result<HttpResponse, HttpResponse> {
        // Create session cookies - use IP binding if enabled
        let session_cookie = if self.bind_session_to_ip {
            self.create_session_cookie_with_context(session, req)
        } else {
            self.create_session_cookie(session)
        }
        .map_err(|e| {
            log::error!("Failed to create session cookie: {e}");
            Self::create_service_error_response("Session creation failed")
        })?;

        let user_cookie = self
            .create_user_cookie_with_persistence(req, user_data)
            .map_err(|e| {
                log::error!("Failed to create user cookie: {e}");
                Self::create_service_error_response("Session creation failed")
            })?;

        // Return JSON response with cookies
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

    // =============================================================================
    // Conversion Utilities for Authentication Results
    // =============================================================================

    /// Convert OAuth session result to common `AuthenticationResult`
    ///
    /// This method provides a bridge between the OAuth-specific result type
    /// and the unified authentication result type.
    #[must_use]
    pub fn oauth_to_auth_result(
        oauth_result: crate::oauth::OAuthSessionResult,
    ) -> crate::models::auth::AuthenticationResult {
        oauth_result.into_auth_result()
    }

    /// Convert Passkey session result to common `AuthenticationResult`
    ///
    /// This method provides a bridge between the Passkey-specific result type
    /// and the unified authentication result type.
    #[must_use]
    pub fn passkey_to_auth_result(
        passkey_result: crate::passkey::PasskeySessionResult,
    ) -> crate::models::auth::AuthenticationResult {
        passkey_result.into_auth_result()
    }

    /// Create `AuthenticationResult` directly from session and user data
    ///
    /// This method allows creating authentication results directly from
    /// session and user data, useful for custom authentication flows.
    #[must_use]
    pub fn create_auth_result(
        session: VouchrsSession,
        user_data: VouchrsUserData,
        redirect_url: Option<String>,
    ) -> crate::models::auth::AuthenticationResult {
        crate::models::auth::AuthenticationResult::new(session, user_data, redirect_url)
    }

    /// Create service unavailable response
    fn create_service_unavailable_response(service_name: &str) -> HttpResponse {
        log::error!("{service_name} service is not available");
        HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": "service_unavailable",
            "message": format!("{service_name} authentication is not enabled")
        }))
    }

    /// Create service error response
    fn create_service_error_response(message: &str) -> HttpResponse {
        HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "authentication_failed",
            "message": message
        }))
    }

    /// Generic method to create a cookie with encrypted data
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails
    pub fn create_cookie<T: Serialize>(
        &self,
        name: String,
        data: Option<&T>,
        options: CookieOptions,
    ) -> Result<Cookie<'static>> {
        let value = match data {
            Some(data) => encrypt_data(data, &self.encryption_key)?,
            None => String::new(),
        };

        Ok(Cookie::build(name, value)
            .http_only(options.http_only)
            .secure(self.cookie_secure && options.secure)
            .same_site(options.same_site)
            .path(options.path)
            .max_age(options.max_age)
            .finish())
    }

    /// Create an encrypted session cookie with optional client IP binding
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails
    pub fn create_session_cookie_with_context(
        &self,
        session: &VouchrsSession,
        req: &HttpRequest,
    ) -> Result<Cookie> {
        if self.bind_session_to_ip {
            // Extract client IP for IP binding
            let (client_ip, _) = crate::session::utils::extract_client_info(req);

            // Create a session copy with bound IP
            let mut bound_session = session.clone();
            bound_session.client_ip = client_ip;

            log::debug!(
                "Creating session cookie with IP binding: {:?}",
                bound_session.client_ip
            );

            self.create_cookie(
                COOKIE_NAME.to_string(),
                Some(&bound_session),
                CookieOptions {
                    same_site: actix_web::cookie::SameSite::Lax,
                    max_age: actix_web::cookie::time::Duration::hours(
                        i64::try_from(self.session_duration_hours).unwrap_or(24),
                    ),
                    ..Default::default()
                },
            )
        } else {
            // Use existing method for no IP binding
            self.create_session_cookie(session)
        }
    }

    /// Validate session IP binding against current request
    ///
    /// # Arguments
    /// * `session` - The session to validate
    /// * `req` - The current HTTP request
    ///
    /// Returns true if IP binding is disabled or if IPs match
    #[must_use]
    pub fn validate_session_ip_binding(&self, session: &VouchrsSession, req: &HttpRequest) -> bool {
        if !self.bind_session_to_ip {
            // IP binding is disabled, always valid
            return true;
        }

        // Extract current client IP
        let (current_ip, _) = crate::session::utils::extract_client_info(req);

        match (&session.client_ip, current_ip) {
            (Some(session_ip), Some(current_ip)) => {
                let is_valid = session_ip == &current_ip;
                if !is_valid {
                    log::warn!(
                        "Session IP mismatch: session IP '{session_ip}' != current IP '{current_ip}'"
                    );
                }
                is_valid
            }
            (Some(session_ip), None) => {
                log::warn!("Session has bound IP '{session_ip}' but current request has no IP");
                false
            }
            (None, Some(current_ip)) => {
                log::warn!("Session has no bound IP but current request has IP '{current_ip}'");
                false
            }
            (None, None) => {
                // Both are None, this is valid (though unusual)
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{constants::TEST_JWT_KEY, RequestBuilder, TestFixtures};
    use chrono::Duration;
    use serde_json::json;

    #[test]
    fn test_token_encryption_decryption() {
        let manager = TestFixtures::session_manager();
        let session = TestFixtures::oauth_session();

        // Test encryption with generic method
        let encrypted = encrypt_data(&session, manager.encryption_key()).unwrap();
        assert!(!encrypted.is_empty());

        // Test decryption with generic method
        let decrypted: VouchrsSession = decrypt_data(&encrypted, manager.encryption_key()).unwrap();
        assert_eq!(session.provider, decrypted.provider);
        assert_eq!(session.id_token, decrypted.id_token);
        assert_eq!(session.refresh_token, decrypted.refresh_token);
        assert_eq!(session.expires_at, decrypted.expires_at);
    }

    #[test]
    fn test_needs_token_refresh() {
        let manager = TestFixtures::session_manager();
        // Session with token expiring in 10 minutes (should NOT need refresh)
        let mut session = TestFixtures::oauth_session();
        session.expires_at = Utc::now() + Duration::minutes(10);
        assert!(!manager.needs_token_refresh(&session));
        // Session with token expiring in 2 minutes (should need refresh)
        session.expires_at = Utc::now() + Duration::minutes(2);
        assert!(manager.needs_token_refresh(&session));
        // Session with expired token (should need refresh)
        session.expires_at = Utc::now() - Duration::minutes(10);
        assert!(manager.needs_token_refresh(&session));
    }

    #[test]
    fn test_create_session_cookie() {
        let manager = TestFixtures::session_manager();
        let session = TestFixtures::oauth_session();

        // Test session cookie creation via SessionManager
        let cookie = manager.create_session_cookie(&session).unwrap();
        assert_eq!(cookie.name(), COOKIE_NAME);
        assert!(!cookie.value().is_empty());

        // Verify we can decrypt the cookie
        let decrypted: VouchrsSession =
            crate::utils::crypto::decrypt_data(cookie.value(), manager.encryption_key()).unwrap();
        assert_eq!(session.provider, decrypted.provider);
        assert_eq!(session.id_token, decrypted.id_token);
    }

    #[test]
    fn test_cookie_refresh() {
        let session = TestFixtures::oauth_session();

        // Test with refresh enabled (2 hours)
        let manager_with_refresh = TestFixtures::session_manager_with_refresh(2);
        assert!(manager_with_refresh.is_cookie_refresh_enabled());

        // Create normal and refreshed cookies
        let normal_cookie = manager_with_refresh
            .create_session_cookie(&session)
            .unwrap();
        let refreshed_cookie = manager_with_refresh
            .create_refreshed_session_cookie(&session)
            .unwrap();

        // Both should have correct name and valid content
        assert_eq!(normal_cookie.name(), COOKIE_NAME);
        assert_eq!(refreshed_cookie.name(), COOKIE_NAME);
        assert!(!normal_cookie.value().is_empty());
        assert!(!refreshed_cookie.value().is_empty());

        // Test with refresh disabled (default)
        let manager_no_refresh = TestFixtures::session_manager(); // Uses 0 refresh hours
        assert!(!manager_no_refresh.is_cookie_refresh_enabled());

        // Refreshed cookie should behave same as normal when disabled
        let disabled_normal = manager_no_refresh.create_session_cookie(&session).unwrap();
        let disabled_refreshed = manager_no_refresh
            .create_refreshed_session_cookie(&session)
            .unwrap();
        assert_eq!(disabled_refreshed.max_age(), disabled_normal.max_age());
    }

    #[test]
    fn test_client_context_hashing() {
        let manager = TestFixtures::session_manager();

        // Test hashing with different values
        let hash1 = manager.calculate_client_context_hash(
            Some("192.168.1.1"),
            Some("Mozilla/5.0"),
            Some("Windows"),
        );
        let hash2 = manager.calculate_client_context_hash(
            Some("192.168.1.1"),
            Some("Mozilla/5.0"),
            Some("Windows"),
        );

        // Same values should produce same hash
        assert_eq!(hash1, hash2);
        assert!(!hash1.is_empty());
        assert_eq!(hash1.len(), 64); // SHA256 produces 64-character hex strings

        // Different values should produce different hashes
        let hash3 = manager.calculate_client_context_hash(
            Some("192.168.1.2"), // Different IP
            Some("Mozilla/5.0"),
            Some("Windows"),
        );
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_session_expiration_validation() {
        let manager = TestFixtures::session_manager();

        let req = RequestBuilder::browser("/");

        // Create user data with recent session start (should be valid)
        let recent_user_data = VouchrsUserData {
            email: "test@example.com".to_string(),
            name: Some("Test User".to_string()),
            provider: "google".to_string(),
            provider_id: "123456789".to_string(),
            client_ip: None, // Test request has no IP
            user_agent: Some(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36".to_string(),
            ),
            platform: Some("macOS".to_string()),
            lang: Some("en-US".to_string()),
            mobile: 0,
            session_start: Some(Utc::now().timestamp()), // Recent session
        };

        // Should be valid and not expired
        assert!(manager
            .validate_session_security(&recent_user_data, &req)
            .unwrap());
        assert!(!manager.is_session_expired(&recent_user_data));

        // Create user data with old session start (should be expired but still valid for refresh)
        let expired_user_data = VouchrsUserData {
            email: "test@example.com".to_string(),
            name: Some("Test User".to_string()),
            provider: "google".to_string(),
            provider_id: "123456789".to_string(),
            client_ip: None, // Test request has no IP
            user_agent: Some(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36".to_string(),
            ),
            platform: Some("macOS".to_string()),
            lang: Some("en-US".to_string()),
            mobile: 0,
            session_start: Some((Utc::now() - chrono::Duration::hours(2)).timestamp()), // 2 hours ago (expired)
        };

        // Should be expired but client context is still valid (can be refreshed)
        assert!(!manager
            .validate_session_security(&expired_user_data, &req)
            .unwrap());
        assert!(manager.is_session_expired(&expired_user_data));
        assert!(manager.validate_client_context_only(&expired_user_data, &req));
    }

    #[test]
    fn test_session_hijacking_prevention() {
        let manager = TestFixtures::session_manager();

        // Test different request types to simulate hijacking attempts
        let browser_req = RequestBuilder::browser("/");
        let mobile_req = RequestBuilder::mobile("/");
        let api_req = RequestBuilder::api_post("/test", json!({}));

        // Valid user data for browser request
        let browser_user_data = VouchrsUserData {
            email: "test@example.com".to_string(),
            name: Some("Test User".to_string()),
            provider: "google".to_string(),
            provider_id: "123456789".to_string(),
            client_ip: None, // Test requests have no IP
            user_agent: Some(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36".to_string(),
            ),
            platform: Some("macOS".to_string()),
            lang: Some("en-US".to_string()),
            mobile: 0,
            session_start: Some(Utc::now().timestamp()),
        };

        // Valid user data for mobile request
        let mobile_user_data = VouchrsUserData {
            email: "test@example.com".to_string(),
            name: Some("Test User".to_string()),
            provider: "google".to_string(),
            provider_id: "123456789".to_string(),
            client_ip: None,
            user_agent: Some("Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)".to_string()),
            platform: Some("iOS".to_string()),
            lang: Some("en-US".to_string()),
            mobile: 1,
            session_start: Some(Utc::now().timestamp()),
        };

        // Valid sessions should pass client context validation
        assert!(manager.validate_client_context_only(&browser_user_data, &browser_req));
        assert!(manager.validate_client_context_only(&mobile_user_data, &mobile_req));

        // Cross-platform hijacking attempts should fail client context validation
        assert!(!manager.validate_client_context_only(&browser_user_data, &mobile_req)); // Browser session on mobile
        assert!(!manager.validate_client_context_only(&mobile_user_data, &browser_req)); // Mobile session on browser
        assert!(!manager.validate_client_context_only(&browser_user_data, &api_req)); // Browser session on API client

        // Different IP addresses should fail client context validation (simulate IP-based hijacking)
        let different_ip_data = VouchrsUserData {
            client_ip: Some("10.0.0.1".to_string()), // Different IP
            ..browser_user_data.clone()
        };
        // Note: This would fail if the test request had an IP, but since test requests have None for IP,
        // this test demonstrates the concept even though both have different values
        assert!(!manager.validate_client_context_only(&different_ip_data, &browser_req));
    }

    #[test]
    fn test_expired_session_with_refresh_token() {
        let manager = TestFixtures::session_manager();

        // Create an expired session with a refresh token
        let mut expired_session = TestFixtures::oauth_session();
        expired_session.expires_at = Utc::now() - chrono::Duration::hours(1); // Expired 1 hour ago
        expired_session.refresh_token = Some("valid_refresh_token".to_string());

        // Test extract_session - should succeed because refresh token is present
        let cookie_value =
            crate::utils::crypto::encrypt_data(&expired_session, manager.encryption_key()).unwrap();
        let result = manager.decrypt_and_validate_session(&cookie_value);
        assert!(
            result.is_ok(),
            "Session with refresh token should be allowed through even if expired"
        );

        // Create an expired session without a refresh token
        let mut expired_session_no_refresh = TestFixtures::oauth_session();
        expired_session_no_refresh.expires_at = Utc::now() - chrono::Duration::hours(1); // Expired 1 hour ago
        expired_session_no_refresh.refresh_token = None;

        // Test extract_session - should fail because no refresh token
        let cookie_value_no_refresh = crate::utils::crypto::encrypt_data(
            &expired_session_no_refresh,
            manager.encryption_key(),
        )
        .unwrap();
        let result_no_refresh = manager.decrypt_and_validate_session(&cookie_value_no_refresh);
        assert!(
            result_no_refresh.is_err(),
            "Session without refresh token should fail when expired"
        );
        assert!(result_no_refresh
            .unwrap_err()
            .to_string()
            .contains("no refresh token available"));
    }

    #[test]
    fn test_ip_binding_validation() {
        // Test with IP binding enabled
        let manager = SessionManager::new(
            TEST_JWT_KEY,
            false,
            true, // bind_session_to_ip = true
            24,
            1,
            0,
        );

        let session_with_ip = VouchrsSession {
            id_token: Some("test_token".to_string()),
            refresh_token: Some("refresh_token".to_string()),
            credential_id: None,
            user_handle: None,
            provider: "google".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
            authenticated_at: Utc::now(),
            client_ip: Some("192.168.1.1".to_string()),
        };

        let session_without_ip = VouchrsSession {
            id_token: Some("test_token".to_string()),
            refresh_token: Some("refresh_token".to_string()),
            credential_id: None,
            user_handle: None,
            provider: "google".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
            authenticated_at: Utc::now(),
            client_ip: None,
        };

        // Create mock requests with different IPs
        let req_with_matching_ip = RequestBuilder::new()
            .uri("/")
            .browser_headers()
            .with_client_ip("192.168.1.1")
            .build();
        let req_with_different_ip = RequestBuilder::new()
            .uri("/")
            .browser_headers()
            .with_client_ip("192.168.1.2")
            .build();
        let req_without_ip = RequestBuilder::browser("/");

        // Test IP binding validation
        assert!(manager.validate_session_ip_binding(&session_with_ip, &req_with_matching_ip));
        assert!(!manager.validate_session_ip_binding(&session_with_ip, &req_with_different_ip));
        assert!(!manager.validate_session_ip_binding(&session_with_ip, &req_without_ip));

        // Session without IP should fail when binding is enabled
        assert!(!manager.validate_session_ip_binding(&session_without_ip, &req_with_matching_ip));

        // Test with IP binding disabled
        let manager_no_binding = SessionManager::new(
            TEST_JWT_KEY,
            false,
            false, // bind_session_to_ip = false
            24,
            1,
            0,
        );

        // All combinations should pass when IP binding is disabled
        assert!(
            manager_no_binding.validate_session_ip_binding(&session_with_ip, &req_with_matching_ip)
        );
        assert!(manager_no_binding
            .validate_session_ip_binding(&session_with_ip, &req_with_different_ip));
        assert!(manager_no_binding.validate_session_ip_binding(&session_with_ip, &req_without_ip));
        assert!(manager_no_binding
            .validate_session_ip_binding(&session_without_ip, &req_with_matching_ip));
    }

    #[test]
    fn test_session_cookie_creation_with_ip_binding() {
        // Test with IP binding enabled
        let manager = SessionManager::new(
            TEST_JWT_KEY,
            false,
            true, // bind_session_to_ip = true
            24,
            1,
            0,
        );

        let session = TestFixtures::oauth_session();
        let req = RequestBuilder::new()
            .uri("/")
            .browser_headers()
            .with_client_ip("192.168.1.1")
            .build();

        // Create session cookie with IP binding
        let cookie = manager
            .create_session_cookie_with_context(&session, &req)
            .unwrap();
        assert_eq!(cookie.name(), COOKIE_NAME);
        assert!(!cookie.value().is_empty());

        // Decrypt and verify IP was bound
        let decrypted: VouchrsSession =
            crate::utils::crypto::decrypt_data(cookie.value(), manager.encryption_key()).unwrap();
        assert_eq!(decrypted.client_ip, Some("192.168.1.1".to_string()));
        assert_eq!(decrypted.provider, session.provider);

        // Test without IP binding
        let manager_no_binding = SessionManager::new(
            TEST_JWT_KEY,
            false,
            false, // bind_session_to_ip = false
            24,
            1,
            0,
        );

        let cookie_no_binding = manager_no_binding
            .create_session_cookie_with_context(&session, &req)
            .unwrap();
        let decrypted_no_binding: VouchrsSession = crate::utils::crypto::decrypt_data(
            cookie_no_binding.value(),
            manager_no_binding.encryption_key(),
        )
        .unwrap();
        assert_eq!(decrypted_no_binding.client_ip, None);
    }

    #[test]
    fn test_session_extraction_with_ip_validation() {
        let manager = SessionManager::new(
            TEST_JWT_KEY,
            false,
            true, // bind_session_to_ip = true
            24,
            1,
            0,
        );

        // Create a session with IP binding
        let session = VouchrsSession {
            id_token: Some("test_token".to_string()),
            refresh_token: Some("refresh_token".to_string()),
            credential_id: None,
            user_handle: None,
            provider: "google".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
            authenticated_at: Utc::now(),
            client_ip: Some("192.168.1.1".to_string()),
        };

        // Create encrypted cookie
        let cookie_value =
            crate::utils::crypto::encrypt_data(&session, manager.encryption_key()).unwrap();

        let req_matching_ip = RequestBuilder::new()
            .uri("/")
            .browser_headers()
            .with_client_ip("192.168.1.1")
            .with_cookie_header(&format!("vouchrs_session={cookie_value}"))
            .build();

        let req_different_ip = RequestBuilder::new()
            .uri("/")
            .browser_headers()
            .with_client_ip("192.168.1.2")
            .with_cookie_header(&format!("vouchrs_session={cookie_value}"))
            .build();

        // Extraction should succeed with matching IP
        let extracted_session = manager.extract_session(&req_matching_ip);
        assert!(extracted_session.is_ok());
        assert_eq!(
            extracted_session.unwrap().client_ip,
            Some("192.168.1.1".to_string())
        );

        // Extraction should fail with different IP
        let extraction_result = manager.extract_session(&req_different_ip);
        assert!(extraction_result.is_err());
        assert!(extraction_result
            .unwrap_err()
            .to_string()
            .contains("IP validation failed"));
    }

    #[test]
    fn test_ip_binding_getter() {
        let manager_with_binding = SessionManager::new(
            TEST_JWT_KEY,
            false,
            true, // bind_session_to_ip = true
            24,
            1,
            0,
        );

        let manager_without_binding = SessionManager::new(
            TEST_JWT_KEY,
            false,
            false, // bind_session_to_ip = false
            24,
            1,
            0,
        );

        assert!(manager_with_binding.is_session_ip_binding_enabled());
        assert!(!manager_without_binding.is_session_ip_binding_enabled());
    }
}
