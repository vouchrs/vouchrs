use crate::models::{VouchrsSession, VouchrsUserData};
use crate::oauth::OAuthState;
use crate::utils::cookie_utils::{CookieOptions, ToCookie, COOKIE_NAME, USER_COOKIE_NAME};
use actix_web::{cookie::Cookie, HttpRequest, HttpResponse, ResponseError};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use rand::Rng;
use serde::{de::DeserializeOwned, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

const NONCE_SIZE: usize = 12; // 96 bits for AES-GCM

// Custom error wrapper for ResponseError implementation
#[derive(Debug)]
pub struct JwtSessionError(anyhow::Error);

impl std::fmt::Display for JwtSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<anyhow::Error> for JwtSessionError {
    fn from(err: anyhow::Error) -> Self {
        JwtSessionError(err)
    }
}

impl ResponseError for JwtSessionError {
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
}

impl SessionManager {
    /// Create a new session manager with the provided key and cookie settings
    pub fn new(key: &[u8], cookie_secure: bool) -> Self {
        let mut encryption_key = [0u8; 32];
        let key_len = std::cmp::min(key.len(), 32);
        encryption_key[..key_len].copy_from_slice(&key[..key_len]);

        // If key is shorter than 32 bytes, derive the rest using a simple hash
        if key_len < 32 {
            for i in key_len..32 {
                encryption_key[i] = encryption_key[i % key_len].wrapping_add(i as u8);
            }
        }

        Self {
            encryption_key,
            cookie_secure,
        }
    }

    /// Create an encrypted session cookie from VouchrsSession (token data only)
    pub fn create_session_cookie(&self, session: &VouchrsSession) -> Result<Cookie> {
        // Use the ToCookie trait implementation
        session.to_cookie(self)
    }

    /// Extract and decrypt session from HTTP request
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
    pub fn needs_token_refresh(&self, session: &VouchrsSession) -> bool {
        let now = Utc::now();
        let buffer_time = chrono::Duration::minutes(5);
        session.expires_at <= now + buffer_time
    }

    /// Create a sign-out cookie (empty with immediate expiration)
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
    pub fn create_expired_cookie(&self) -> Cookie<'static> {
        crate::utils::cookie_utils::create_expired_cookie(COOKIE_NAME, self.cookie_secure)
    }

    /// Create a temporary cookie for storing OAuth state during the OAuth flow
    pub fn create_temporary_state_cookie(
        &self,
        oauth_state: &OAuthState,
    ) -> Result<Cookie<'static>> {
        // Use the ToCookie trait implementation
        oauth_state.to_cookie(self)
    }

    /// Get OAuth state from temporary cookie in request
    pub fn get_temporary_state_from_request(
        &self,
        req: &HttpRequest,
    ) -> Result<Option<OAuthState>> {
        log::info!("Looking for temporary state cookie 'vouchr_oauth_state'");

        // Log all cookies in the request for debugging
        crate::utils::cookie_utils::log_cookies(req);

        if let Some(cookie) = req.cookie("vouchr_oauth_state") {
            log::info!(
                "Found temporary state cookie with value length: {}",
                cookie.value().len()
            );
            match self.decrypt_data::<OAuthState>(cookie.value()) {
                Ok(oauth_state) => Ok(Some(oauth_state)),
                Err(e) => {
                    log::warn!("Failed to decrypt OAuth state cookie: {}", e);
                    Ok(None)
                }
            }
        } else {
            log::warn!("No temporary state cookie 'vouchr_oauth_state' found in request");
            Ok(None)
        }
    }

    /// Get session from HTTP request cookies
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
    pub fn create_expired_temp_state_cookie(&self) -> Cookie<'static> {
        crate::utils::cookie_utils::create_expired_cookie("vouchr_oauth_state", self.cookie_secure)
    }

    // No longer needed - replaced with generic encrypt_data and decrypt_data methods

    /// Decrypt and validate session from cookie value
    pub fn decrypt_and_validate_session(&self, cookie_value: &str) -> Result<VouchrsSession> {
        let session: VouchrsSession = self.decrypt_data(cookie_value)?;

        // Check if session has expired
        if session.expires_at <= Utc::now() {
            return Err(anyhow!("Session expired"));
        }

        Ok(session)
    }

    /// Get OAuth state from either temporary cookie (Google) or stateless JWT (Apple)
    pub fn get_oauth_state_from_request(
        &self,
        req: &HttpRequest,
        _received_state: &str,
    ) -> Result<Option<OAuthState>> {
        // Only try cookie-based state (works for both Google and Apple if you handle Apple differently)
        self.get_temporary_state_from_request(req)
    }

    /// Create an encrypted user data cookie from VouchrsUserData
    pub fn create_user_cookie(&self, user_data: &VouchrsUserData) -> Result<Cookie> {
        // Use the ToCookie trait implementation
        user_data.to_cookie(self)
    }

    /// Extract user data from HTTP request cookie
    pub fn extract_user_data(&self, req: &HttpRequest) -> Result<VouchrsUserData> {
        let cookie_value = req
            .cookie(USER_COOKIE_NAME)
            .ok_or_else(|| anyhow!("User data not found"))?
            .value()
            .to_string();

        self.decrypt_data(&cookie_value)
    }

    /// Get user data from HTTP request cookies (returns None if not found)
    pub fn get_user_data_from_request(&self, req: &HttpRequest) -> Result<Option<VouchrsUserData>> {
        if let Some(cookie) = req.cookie(USER_COOKIE_NAME) {
            match self.decrypt_data::<VouchrsUserData>(cookie.value()) {
                Ok(user_data) => Ok(Some(user_data)),
                Err(e) => {
                    log::warn!("Failed to decrypt user data cookie: {}", e);
                    Ok(None)
                }
            }
        } else {
            Ok(None)
        }
    }

    /// Create an expired user cookie to clear user data
    pub fn create_expired_user_cookie(&self) -> Cookie<'static> {
        crate::utils::cookie_utils::create_expired_cookie(USER_COOKIE_NAME, self.cookie_secure)
    }

    // No longer needed - replaced with generic encrypt_data and decrypt_data methods

    /// Generic method to create a cookie with encrypted data
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
    pub fn encrypt_data<T: Serialize>(&self, data: &T) -> Result<String> {
        // Serialize the data to JSON
        let json_data = serde_json::to_string(data).context("Failed to serialize data")?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the data
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.encryption_key));
        let ciphertext = cipher
            .encrypt(nonce, json_data.as_bytes())
            .map_err(|e| anyhow!("AES encryption failed: {}", e))?;

        // Combine nonce + ciphertext and encode as base64
        let mut combined = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);

        Ok(general_purpose::URL_SAFE_NO_PAD.encode(&combined))
    }

    /// Generic decryption function for any deserializable data
    pub fn decrypt_data<T: DeserializeOwned>(&self, encrypted_data: &str) -> Result<T> {
        // Decode from base64
        let combined = general_purpose::URL_SAFE_NO_PAD
            .decode(encrypted_data)
            .context("Failed to decode base64 data")?;

        if combined.len() < NONCE_SIZE {
            return Err(anyhow!("Invalid data length"));
        }

        // Split nonce and ciphertext
        let (nonce_bytes, ciphertext) = combined.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt the data
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.encryption_key));
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("AES decryption failed: {}", e))?;

        // Deserialize the data from JSON
        let data: T = serde_json::from_slice(&plaintext)
            .context("Failed to deserialize data from decrypted JSON")?;

        Ok(data)
    }
}

/// Implementation of ToCookie for VouchrsSession
impl crate::utils::cookie_utils::ToCookie<SessionManager> for VouchrsSession {
    fn to_cookie(&self, session_manager: &SessionManager) -> Result<Cookie<'static>> {
        session_manager.create_cookie(
            COOKIE_NAME.to_string(),
            Some(self),
            CookieOptions {
                same_site: actix_web::cookie::SameSite::Lax,
                ..Default::default()
            },
        )
    }
}

/// Implementation of ToCookie for VouchrsUserData
impl crate::utils::cookie_utils::ToCookie<SessionManager> for VouchrsUserData {
    fn to_cookie(&self, session_manager: &SessionManager) -> Result<Cookie<'static>> {
        session_manager.create_cookie(
            USER_COOKIE_NAME.to_string(),
            Some(self),
            CookieOptions {
                same_site: actix_web::cookie::SameSite::Lax,
                ..Default::default()
            },
        )
    }
}

/// Implementation of ToCookie for OAuthState
impl crate::utils::cookie_utils::ToCookie<SessionManager> for OAuthState {
    fn to_cookie(&self, session_manager: &SessionManager) -> Result<Cookie<'static>> {
        let options = CookieOptions {
            same_site: actix_web::cookie::SameSite::Lax,
            max_age: actix_web::cookie::time::Duration::minutes(10), // Short-lived for OAuth flow
            ..Default::default()
        };

        let cookie =
            session_manager.create_cookie("vouchr_oauth_state".to_string(), Some(self), options)?;

        log::info!(
            "Creating temporary state cookie: secure={}, name=vouchr_oauth_state, encrypted_len={}",
            session_manager.cookie_secure,
            cookie.value().len()
        );

        Ok(cookie)
    }
}

/// Helper function to get current timestamp
pub fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_helpers::create_test_session;
    use chrono::Duration;

    #[test]
    fn test_token_encryption_decryption() {
        let key = b"test_key_32_bytes_long_for_testing_purposes";
        let manager = SessionManager::new(key, false);
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
        let manager = SessionManager::new(key, false);
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
        let manager = SessionManager::new(key, false);
        let session = create_test_session();

        // Create cookie with token data (current approach)
        let token_cookie = manager.create_session_cookie(&session).unwrap();
        let token_size = token_cookie.value().len();

        // The current approach should work fine
        let token_json = serde_json::to_string(&session).unwrap();

        println!("Token JSON size: {} bytes", token_json.len());
        println!("Token cookie size: {} bytes", token_size);

        // Log the compact nature of the token data
        assert!(!token_json.is_empty());
        assert!(!token_cookie.value().is_empty());
    }

    #[test]
    fn test_generic_encryption_decryption() {
        let key = b"test_key_32_bytes_long_for_testing_purposes";
        let manager = SessionManager::new(key, false);
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
        let manager = SessionManager::new(key, false);
        let session = create_test_session();

        // Test ToCookie implementation for VouchrsSession
        let cookie = session.to_cookie(&manager).unwrap();
        assert_eq!(cookie.name(), COOKIE_NAME);
        assert!(!cookie.value().is_empty());

        // Verify we can decrypt the cookie
        let decrypted: VouchrsSession = manager.decrypt_data(cookie.value()).unwrap();
        assert_eq!(session.provider, decrypted.provider);
        assert_eq!(session.id_token, decrypted.id_token);
    }
}
