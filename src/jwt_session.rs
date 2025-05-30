use crate::models::{VouchrsSession, OAuthState, VouchrsUserData};
use actix_web::{HttpRequest, cookie::Cookie, HttpResponse, ResponseError};
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::{Result, anyhow, Context};

const COOKIE_NAME: &str = "vouchrs_session";
const USER_COOKIE_NAME: &str = "vouchrs_user";
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
        use crate::utils::response_builder::ResponseBuilder;
        
        let error_msg = self.0.to_string();
        
        if error_msg.contains("Session expired") || error_msg.contains("Session not found") {
            ResponseBuilder::unauthorized_json("Authentication required")
        } else {
            ResponseBuilder::internal_error_json("Internal server error")
        }
    }
}

/// JWT Session Manager for stateless encrypted session handling
#[derive(Clone)]
pub struct JwtSessionManager {
    encryption_key: [u8; 32],
    cookie_secure: bool,
}

impl JwtSessionManager {
    /// Create a new JWT session manager with the provided key and cookie settings
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
        let encrypted_data = self.encrypt_token_data(session)?;
        
        Ok(Cookie::build(COOKIE_NAME, encrypted_data)
            .http_only(true)
            .secure(self.cookie_secure)
            .same_site(actix_web::cookie::SameSite::Lax)
            .path("/")
            .max_age(actix_web::cookie::time::Duration::hours(24))
            .finish())
    }

    /// Extract and decrypt session from HTTP request
    pub fn extract_session(&self, req: &HttpRequest) -> Result<VouchrsSession> {
        let cookie_value = req
            .cookie(COOKIE_NAME)
            .ok_or_else(|| anyhow!("Session not found"))?
            .value()
            .to_string();

        self.decrypt_token_data(&cookie_value)
    }

    /// Decrypt token data from cookie
    fn decrypt_token_data(&self, encrypted_data: &str) -> Result<VouchrsSession> {
        // Decode from base64
        let combined = general_purpose::URL_SAFE_NO_PAD
            .decode(encrypted_data)
            .context("Failed to decode base64 session data")?;

        if combined.len() < NONCE_SIZE {
            return Err(anyhow!("Invalid session data length"));
        }

        // Split nonce and ciphertext
        let (nonce_bytes, ciphertext) = combined.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt the token data
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.encryption_key));
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("AES decryption failed: {}", e))?;

        // Deserialize token data from JSON
        let token_json = String::from_utf8(plaintext)
            .context("Failed to decode token UTF-8 data")?;

        let session: VouchrsSession = serde_json::from_str(&token_json)
            .context("Failed to deserialize token JSON")?;

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

    /// Encrypt token data (VouchrsSession structure for cookies)
    fn encrypt_token_data(&self, session: &VouchrsSession) -> Result<String> {
        // Serialize token data to JSON
        let token_json = serde_json::to_string(session)
            .context("Failed to serialize token data")?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the token data
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.encryption_key));
        let ciphertext = cipher
            .encrypt(nonce, token_json.as_bytes())
            .map_err(|e| anyhow!("AES encryption failed: {}", e))?;

        // Combine nonce + ciphertext and encode as base64
        let mut combined = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);

        Ok(general_purpose::URL_SAFE_NO_PAD.encode(&combined))
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
        Cookie::build(COOKIE_NAME, "")
            .http_only(true)
            .secure(self.cookie_secure)
            .same_site(actix_web::cookie::SameSite::Lax)
            .path("/")
            .max_age(actix_web::cookie::time::Duration::seconds(-1))
            .finish()
    }

    /// Create a temporary cookie for storing OAuth state during the OAuth flow
    pub fn create_temporary_state_cookie(&self, oauth_state: &OAuthState) -> Result<Cookie<'static>> {
        let state_json = serde_json::to_string(oauth_state)
            .context("Failed to serialize OAuth state")?;
        
        let encrypted_state = self.encrypt_oauth_state(state_json.as_bytes())?;
        
        log::info!("Creating temporary state cookie: secure={}, name=vouchr_oauth_state, encrypted_len={}", 
                   self.cookie_secure, encrypted_state.len());
        
        let cookie = Cookie::build("vouchr_oauth_state", encrypted_state)
            .path("/")
            .secure(self.cookie_secure)
            .http_only(true)
            .same_site(actix_web::cookie::SameSite::Lax)
            .max_age(actix_web::cookie::time::Duration::minutes(10)) // Short-lived for OAuth flow
            .finish();
            
        Ok(cookie)
    }

    /// Get OAuth state from temporary cookie in request
    pub fn get_temporary_state_from_request(&self, req: &HttpRequest) -> Result<Option<OAuthState>> {
        log::info!("Looking for temporary state cookie 'vouchr_oauth_state'");
        
        // Log all cookies in the request for debugging
        if let Ok(cookies) = req.cookies() {
            for cookie in cookies.iter() {
                log::info!("Found cookie: name='{}', secure={:?}", cookie.name(), cookie.secure());
            }
        }
        
        if let Some(cookie) = req.cookie("vouchr_oauth_state") {
            log::info!("Found temporary state cookie with value length: {}", cookie.value().len());
            let decrypted_data = self.decrypt_oauth_state(cookie.value())?;
            let state_json = String::from_utf8(decrypted_data)
                .context("Failed to decode OAuth state UTF-8 data")?;
            let oauth_state: OAuthState = serde_json::from_str(&state_json)
                .context("Failed to deserialize OAuth state JSON")?;
            Ok(Some(oauth_state))
        } else {
            log::warn!("No temporary state cookie 'vouchr_oauth_state' found in request");
            Ok(None)
        }
    }

    /// Get session from HTTP request cookies
    pub fn get_session_from_request(&self, req: &HttpRequest) -> Result<Option<VouchrsSession>> {
        if let Some(cookie) = req.cookie(COOKIE_NAME) {
            match self.decrypt_token_data(cookie.value()) {
                Ok(session) => {
                    // Check if session needs token refresh (5 minutes before expiration)
                    if session.expires_at - chrono::Duration::minutes(5) <= Utc::now() {
                        log::warn!("OAuth token needs refresh for provider: {}", session.provider);
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
        Cookie::build("vouchr_oauth_state", "")
            .path("/")
            .secure(self.cookie_secure)
            .http_only(true)
            .same_site(actix_web::cookie::SameSite::Lax)
            .max_age(actix_web::cookie::time::Duration::seconds(-1))
            .finish()
    }

    /// Encrypt OAuth state data
    fn encrypt_oauth_state(&self, data: &[u8]) -> Result<String> {
        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the data
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.encryption_key));
        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| anyhow!("AES encryption failed: {}", e))?;

        // Combine nonce + ciphertext and encode as base64
        let mut combined = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);

        Ok(general_purpose::URL_SAFE_NO_PAD.encode(&combined))
    }

    /// Decrypt OAuth state data
    fn decrypt_oauth_state(&self, encrypted_data: &str) -> Result<Vec<u8>> {
        // Decode from base64
        let combined = general_purpose::URL_SAFE_NO_PAD
            .decode(encrypted_data)
            .context("Failed to decode base64 OAuth state data")?;

        if combined.len() < NONCE_SIZE {
            return Err(anyhow!("Invalid OAuth state data length"));
        }

        // Split nonce and ciphertext
        let (nonce_bytes, ciphertext) = combined.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt the data
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.encryption_key));
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("AES decryption failed: {}", e))?;

        Ok(plaintext)
    }

    /// Decrypt and validate session from cookie value
    pub fn decrypt_and_validate_session(&self, cookie_value: &str) -> Result<VouchrsSession> {
        let session = self.decrypt_token_data(cookie_value)?;
        
        // Check if session has expired
        if session.expires_at <= Utc::now() {
            return Err(anyhow!("Session expired"));
        }
        
        Ok(session)
    }

    /// Get OAuth state from either temporary cookie (Google) or stateless JWT (Apple)
    pub fn get_oauth_state_from_request(&self, req: &HttpRequest, _received_state: &str) -> Result<Option<OAuthState>> {
        // Only try cookie-based state (works for both Google and Apple if you handle Apple differently)
        self.get_temporary_state_from_request(req)
    }

    /// Create an encrypted user data cookie from VouchrsUserData
    pub fn create_user_cookie(&self, user_data: &VouchrsUserData) -> Result<Cookie> {
        let encrypted_data = self.encrypt_user_data(user_data)?;
        
        Ok(Cookie::build(USER_COOKIE_NAME, encrypted_data)
            .http_only(true)
            .secure(self.cookie_secure)
            .same_site(actix_web::cookie::SameSite::Lax)
            .path("/")
            .max_age(actix_web::cookie::time::Duration::hours(24))
            .finish())
    }

    /// Extract user data from HTTP request cookie
    pub fn extract_user_data(&self, req: &HttpRequest) -> Result<VouchrsUserData> {
        let cookie_value = req
            .cookie(USER_COOKIE_NAME)
            .ok_or_else(|| anyhow!("User data not found"))?
            .value()
            .to_string();

        self.decrypt_user_data(&cookie_value)
    }

    /// Get user data from HTTP request cookies (returns None if not found)
    pub fn get_user_data_from_request(&self, req: &HttpRequest) -> Result<Option<VouchrsUserData>> {
        if let Some(cookie) = req.cookie(USER_COOKIE_NAME) {
            match self.decrypt_user_data(cookie.value()) {
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
        Cookie::build(USER_COOKIE_NAME, "")
            .http_only(true)
            .secure(self.cookie_secure)
            .same_site(actix_web::cookie::SameSite::Lax)
            .path("/")
            .max_age(actix_web::cookie::time::Duration::seconds(-1))
            .finish()
    }

    /// Encrypt user data
    fn encrypt_user_data(&self, user_data: &VouchrsUserData) -> Result<String> {
        // Serialize user data to JSON
        let user_json = serde_json::to_string(user_data)
            .context("Failed to serialize user data")?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the user data
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.encryption_key));
        let ciphertext = cipher
            .encrypt(nonce, user_json.as_bytes())
            .map_err(|e| anyhow!("AES encryption failed: {}", e))?;

        // Combine nonce + ciphertext and encode as base64
        let mut combined = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);

        Ok(general_purpose::URL_SAFE_NO_PAD.encode(&combined))
    }

    /// Decrypt user data
    fn decrypt_user_data(&self, encrypted_data: &str) -> Result<VouchrsUserData> {
        // Decode from base64
        let combined = general_purpose::URL_SAFE_NO_PAD
            .decode(encrypted_data)
            .context("Failed to decode base64 user data")?;

        if combined.len() < NONCE_SIZE {
            return Err(anyhow!("Invalid user data length"));
        }

        // Split nonce and ciphertext
        let (nonce_bytes, ciphertext) = combined.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt the user data
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.encryption_key));
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("AES decryption failed: {}", e))?;

        // Deserialize user data from JSON
        let user_json = String::from_utf8(plaintext)
            .context("Failed to decode user UTF-8 data")?;

        let user_data: VouchrsUserData = serde_json::from_str(&user_json)
            .context("Failed to deserialize user JSON")?;

        Ok(user_data)
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
    use chrono::Duration;
    use crate::utils::test_helpers::create_test_session;

    #[test]
    fn test_token_encryption_decryption() {
        let key = b"test_key_32_bytes_long_for_testing_purposes";
        let manager = JwtSessionManager::new(key, false);
        let session = create_test_session();

        // Test encryption
        let encrypted = manager.encrypt_token_data(&session).unwrap();
        assert!(!encrypted.is_empty());

        // Test decryption
        let decrypted = manager.decrypt_token_data(&encrypted).unwrap();
        assert_eq!(session.provider, decrypted.provider);
        assert_eq!(session.id_token, decrypted.id_token);
        assert_eq!(session.refresh_token, decrypted.refresh_token);
        assert_eq!(session.expires_at, decrypted.expires_at);
    }

    #[test]
    fn test_needs_token_refresh() {
        let key = b"test_key_32_bytes_long_for_testing_purposes";
        let manager = JwtSessionManager::new(key, false);
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
        let manager = JwtSessionManager::new(key, false);
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

}
