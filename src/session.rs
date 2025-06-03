use crate::models::{VouchrsSession, VouchrsUserData};
use crate::oauth::OAuthState;
use crate::session_validation::{calculate_client_context_hash, validate_client_context};
use crate::utils::cookie::{CookieOptions, COOKIE_NAME, USER_COOKIE_NAME};
use crate::utils::crypto::{decrypt_data, derive_encryption_key, encrypt_data};
use actix_web::{cookie::Cookie, HttpRequest, HttpResponse, ResponseError};
use anyhow::{anyhow, Result};
use chrono::Utc;
use serde::Serialize;

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
            HttpResponse::Unauthorized().json("Authentication required")
        } else {
            HttpResponse::InternalServerError().json("Internal server error")
        }
    }
}

/// Session Manager for stateless encrypted session handling
#[derive(Clone)]
pub struct SessionManager {
    encryption_key: [u8; 32],
    cookie_secure: bool,
    session_duration_hours: u64,
    session_expiration_hours: u64,
    session_refresh_hours: u64,
}

impl SessionManager {
    /// Create a new session manager with cookie refresh configuration
    #[must_use]
    pub fn new(
        key: &[u8],
        cookie_secure: bool,
        session_duration_hours: u64,
        session_expiration_hours: u64,
        session_refresh_hours: u64,
    ) -> Self {
        let encryption_key = derive_encryption_key(key);

        Self {
            encryption_key,
            cookie_secure,
            session_duration_hours,
            session_expiration_hours,
            session_refresh_hours,
        }
    }

    /// Get reference to encryption key for direct use with crypto utils
    #[must_use]
    pub fn encryption_key(&self) -> &[u8] {
        &self.encryption_key
    }

    /// Create an encrypted session cookie from `VouchrsSession` (token data only)
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
    /// - Session has expired
    pub fn extract_session(&self, req: &HttpRequest) -> Result<VouchrsSession> {
        let cookie_value = req
            .cookie(COOKIE_NAME)
            .ok_or_else(|| anyhow!("Session not found"))?
            .value()
            .to_string();

        let session: VouchrsSession = decrypt_data(&cookie_value, &self.encryption_key)?;

        // Check if tokens are expired
        if session.expires_at <= Utc::now() {
            return Err(anyhow!("Session expired"));
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
        crate::utils::cookie::create_expired_cookie(COOKIE_NAME, self.cookie_secure)
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
        let cookie_name = crate::utils::cookie::OAUTH_STATE_COOKIE;
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
        let cookie_name = crate::utils::cookie::OAUTH_STATE_COOKIE;
        log::info!("Looking for temporary state cookie '{cookie_name}'");

        // Log all cookies in the request for debugging
        crate::utils::cookie::log_cookies(req);

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
    /// Returns an error if decryption fails (expired sessions return None)
    pub fn get_session_from_request(&self, req: &HttpRequest) -> Result<Option<VouchrsSession>> {
        if let Some(cookie) = req.cookie(COOKIE_NAME) {
            match decrypt_data::<VouchrsSession>(cookie.value(), &self.encryption_key) {
                Ok(session) => {
                    // Check if session has expired
                    if session.expires_at <= Utc::now() {
                        return Ok(None);
                    }

                    // Check if session needs token refresh (5 minutes before expiration)
                    if session.expires_at - chrono::Duration::minutes(5) <= Utc::now() {
                        log::warn!(
                            "OAuth token needs refresh for provider: {}",
                            session.provider
                        );
                    }
                    Ok(Some(session))
                }
                Err(e) if e.to_string().contains("Session expired") => Ok(None),
                Err(e) => Err(e),
            }
        } else {
            Ok(None)
        }
    }

    /// Decrypt and validate session from cookie value
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Decryption fails
    /// - Session has expired
    pub fn decrypt_and_validate_session(&self, cookie_value: &str) -> Result<VouchrsSession> {
        let session: VouchrsSession = decrypt_data(cookie_value, &self.encryption_key)?;

        // Check if session has expired
        if session.expires_at <= Utc::now() {
            return Err(anyhow!("Session expired"));
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_helpers::{create_test_session, create_test_session_manager};
    use chrono::Duration;

    #[test]
    fn test_token_encryption_decryption() {
        let manager = create_test_session_manager();
        let session = create_test_session();

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
        let manager = create_test_session_manager();
        // Session with token expiring in 10 minutes (should NOT need refresh)
        let mut session = create_test_session();
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
        let manager = create_test_session_manager();
        let session = create_test_session();

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
        let session = create_test_session();

        // Test with refresh enabled (2 hours)
        let manager_with_refresh =
            crate::utils::test_helpers::create_test_session_manager_with_refresh(2);
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
        let manager_no_refresh = create_test_session_manager(); // Uses 0 refresh hours
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
        let manager = create_test_session_manager();

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
        use crate::utils::test_request_builder::TestRequestBuilder;
        let manager = create_test_session_manager();

        let req = TestRequestBuilder::browser_request();

        // Create user data with recent session start (should be valid)
        let recent_user_data = VouchrsUserData {
            email: "test@example.com".to_string(),
            name: Some("Test User".to_string()),
            provider: "google".to_string(),
            provider_id: "123456789".to_string(),
            client_ip: None, // Test request has no IP
            user_agent: Some(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
            ),
            platform: Some("Windows".to_string()),
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
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
            ),
            platform: Some("Windows".to_string()),
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
        use crate::utils::test_request_builder::TestRequestBuilder;

        let manager = create_test_session_manager();

        // Test different request types to simulate hijacking attempts
        let browser_req = TestRequestBuilder::browser_request();
        let mobile_req = TestRequestBuilder::mobile_browser_request();
        let api_req = TestRequestBuilder::api_request();

        // Valid user data for browser request
        let browser_user_data = VouchrsUserData {
            email: "test@example.com".to_string(),
            name: Some("Test User".to_string()),
            provider: "google".to_string(),
            provider_id: "123456789".to_string(),
            client_ip: None, // Test requests have no IP
            user_agent: Some(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
            ),
            platform: Some("Windows".to_string()),
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
            user_agent: Some(
                "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15"
                    .to_string(),
            ),
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
}
