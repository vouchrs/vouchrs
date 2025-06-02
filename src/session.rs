use crate::models::{VouchrsSession, VouchrsUserData};
use crate::oauth::OAuthState;
use crate::utils::cookie::{CookieOptions, COOKIE_NAME, USER_COOKIE_NAME};
use crate::utils::crypto::{derive_encryption_key, encrypt_data, decrypt_data};
use actix_web::{cookie::Cookie, HttpRequest, HttpResponse, ResponseError};
use anyhow::{anyhow, Result};
use chrono::Utc;
use serde::{de::DeserializeOwned, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

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
}

impl SessionManager {
    /// Create a new session manager with the provided key and cookie settings
    #[must_use]
    pub fn new(key: &[u8], cookie_secure: bool, session_duration_hours: u64) -> Self {
        let encryption_key = derive_encryption_key(key);

        Self {
            encryption_key,
            cookie_secure,
            session_duration_hours,
        }
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
                max_age: actix_web::cookie::time::Duration::hours(i64::try_from(self.session_duration_hours).unwrap_or(24)),
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

        let session: VouchrsSession = self.decrypt_data(&cookie_value)?;

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

    /// Create a sign-out cookie (empty with immediate expiration)
    #[must_use]
    pub fn create_signout_cookie(&self) -> Cookie {
        Cookie::build(COOKIE_NAME, "")
            .http_only(true)
            .secure(self.cookie_secure)
            .same_site(actix_web::cookie::SameSite::Lax)
            .path("/")
            .max_age(actix_web::cookie::time::Duration::seconds(0))
            .finish()
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

        req.cookie(cookie_name).map_or_else(|| {
            log::warn!("No temporary state cookie '{cookie_name}' found in request");
            Ok(None)
        }, |cookie| {
            log::info!(
                "Found temporary state cookie with value length: {}",
                cookie.value().len()
            );
            match self.decrypt_data::<OAuthState>(cookie.value()) {
                Ok(oauth_state) => Ok(Some(oauth_state)),
                Err(e) => {
                    log::warn!("Failed to decrypt OAuth state cookie: {e}");
                    Ok(None)
                }
            }
        })
    }

    /// Get session from HTTP request cookies
    /// 
    /// # Errors
    /// 
    /// Returns an error if decryption fails (expired sessions return None)
    pub fn get_session_from_request(&self, req: &HttpRequest) -> Result<Option<VouchrsSession>> {
        if let Some(cookie) = req.cookie(COOKIE_NAME) {
            match self.decrypt_data::<VouchrsSession>(cookie.value()) {
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

    /// Create an expired temporary state cookie to clear it
    #[must_use]
    pub fn create_expired_temp_state_cookie(&self) -> Cookie<'static> {
        crate::utils::cookie::create_expired_cookie(crate::utils::cookie::OAUTH_STATE_COOKIE, self.cookie_secure)
    }

    /// Decrypt and validate session from cookie value
    /// 
    /// # Errors
    /// 
    /// Returns an error if:
    /// - Decryption fails
    /// - Session has expired
    pub fn decrypt_and_validate_session(&self, cookie_value: &str) -> Result<VouchrsSession> {
        let session: VouchrsSession = self.decrypt_data(cookie_value)?;

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
                max_age: actix_web::cookie::time::Duration::hours(i64::try_from(self.session_duration_hours).unwrap_or(24)),
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

        self.decrypt_data(&cookie_value)
    }

    /// Get user data from HTTP request cookies (returns None if not found)
    /// 
    /// # Errors
    /// 
    /// Returns an error if a critical failure occurs (decryption failures return None)
    pub fn get_user_data_from_request(&self, req: &HttpRequest) -> Result<Option<VouchrsUserData>> {
        req.cookie(USER_COOKIE_NAME).map_or_else(|| Ok(None), |cookie| match self.decrypt_data::<VouchrsUserData>(cookie.value()) {
                Ok(user_data) => Ok(Some(user_data)),
                Err(e) => {
                    log::warn!("Failed to decrypt user data cookie: {e}");
                    Ok(None)
                }
            })
    }

    /// Create an expired user cookie to clear user data
    #[must_use]
    pub fn create_expired_user_cookie(&self) -> Cookie<'static> {
        crate::utils::cookie::create_expired_cookie(USER_COOKIE_NAME, self.cookie_secure)
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
            Some(data) => self.encrypt_data(data)?,
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

    /// Generic encryption function for any serializable data
    /// 
    /// # Errors
    /// 
    /// Returns an error if:
    /// - Serialization fails
    /// - AES encryption fails
    pub fn encrypt_data<T: Serialize>(&self, data: &T) -> Result<String> {
        encrypt_data(data, &self.encryption_key)
    }

    /// Generic decryption function for any deserializable data
    /// 
    /// # Errors
    /// 
    /// Returns an error if:
    /// - Base64 decoding fails
    /// - Data length is invalid
    /// - AES decryption fails
    /// - Deserialization fails
    pub fn decrypt_data<T: DeserializeOwned>(&self, encrypted_data: &str) -> Result<T> {
        decrypt_data(encrypted_data, &self.encryption_key)
    }
}



/// Helper function to get current timestamp
/// 
/// # Panics
/// 
/// Panics if the system time is before the Unix epoch (1970-01-01)
#[must_use]
pub fn current_timestamp() -> i64 {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time is before Unix epoch");
    
    // Use try_from to safely convert, but realistically this won't overflow for centuries
    i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_helpers::create_test_session;
    use chrono::Duration;

    #[test]
    fn test_token_encryption_decryption() {
        let key = b"test_key_32_bytes_long_for_testing_purposes";
        let manager = SessionManager::new(key, false, 24);
        let session = create_test_session();

        // Test encryption with generic method
        let encrypted = manager.encrypt_data(&session).unwrap();
        assert!(!encrypted.is_empty());

        // Test decryption with generic method
        let decrypted: VouchrsSession = manager.decrypt_data(&encrypted).unwrap();
        assert_eq!(session.provider, decrypted.provider);
        assert_eq!(session.id_token, decrypted.id_token);
        assert_eq!(session.refresh_token, decrypted.refresh_token);
        assert_eq!(session.expires_at, decrypted.expires_at);
    }

    #[test]
    fn test_needs_token_refresh() {
        let key = b"test_key_32_bytes_long_for_testing_purposes";
        let manager = SessionManager::new(key, false, 24);
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
    fn test_cookie_size_reduction() {
        let key = b"test_key_32_bytes_long_for_testing_purposes";
        let manager = SessionManager::new(key, false, 24);
        let session = create_test_session();

        // Create cookie with token data (current approach)
        let token_cookie = manager.create_session_cookie(&session).unwrap();
        let token_size = token_cookie.value().len();

        // The current approach should work fine
        let token_json = serde_json::to_string(&session).unwrap();

        println!("Token JSON size: {} bytes", token_json.len());
        println!("Token cookie size: {token_size} bytes");

        // Log the compact nature of the token data
        assert!(!token_json.is_empty());
        assert!(!token_cookie.value().is_empty());
    }

    #[test]
    fn test_generic_encryption_decryption() {
        let key = b"test_key_32_bytes_long_for_testing_purposes";
        let manager = SessionManager::new(key, false, 24);
        let session = create_test_session();

        // Test generic encryption
        let encrypted = manager.encrypt_data(&session).unwrap();
        assert!(!encrypted.is_empty());

        // Test generic decryption
        let decrypted: VouchrsSession = manager.decrypt_data(&encrypted).unwrap();
        assert_eq!(session.provider, decrypted.provider);
        assert_eq!(session.id_token, decrypted.id_token);
        assert_eq!(session.refresh_token, decrypted.refresh_token);
        assert_eq!(session.expires_at, decrypted.expires_at);
    }

    #[test]
    fn test_to_cookie_trait() {
        let key = b"test_key_32_bytes_long_for_testing_purposes";
        let manager = SessionManager::new(key, false, 24);
        let session = create_test_session();

        // Test session cookie creation via SessionManager
        let cookie = manager.create_session_cookie(&session).unwrap();
        assert_eq!(cookie.name(), COOKIE_NAME);
        assert!(!cookie.value().is_empty());

        // Verify we can decrypt the cookie
        let decrypted: VouchrsSession = manager.decrypt_data(cookie.value()).unwrap();
        assert_eq!(session.provider, decrypted.provider);
        assert_eq!(session.id_token, decrypted.id_token);
    }
}
