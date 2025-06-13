use actix_web::{cookie::Cookie, HttpRequest};
use anyhow::{anyhow, Result};
use log;
use serde::Serialize;

use crate::models::{VouchrsSession, VouchrsUserData};
use crate::oauth::OAuthState;
use crate::utils::crypto::{decrypt_data, encrypt_data};

/// Common cookie names used across the application
pub const COOKIE_NAME: &str = "vouchrs_session";
pub const USER_COOKIE_NAME: &str = "vouchrs_user";
pub const OAUTH_STATE_COOKIE: &str = "vouchr_oauth_state";

/// Options for cookie creation
pub struct CookieOptions {
    pub http_only: bool,
    pub secure: bool,
    pub same_site: actix_web::cookie::SameSite,
    pub path: String,
    pub max_age: actix_web::cookie::time::Duration,
}

impl Default for CookieOptions {
    fn default() -> Self {
        Self {
            http_only: true,
            secure: true,
            same_site: actix_web::cookie::SameSite::Strict,
            path: "/".to_string(),
            max_age: actix_web::cookie::time::Duration::hours(24),
        }
    }
}

/// Cookie factory for creating encrypted cookies with proper configuration
///
/// This factory centralizes all cookie creation logic and provides a clean interface
/// for creating different types of cookies used throughout the application.
#[derive(Clone)]
pub struct CookieFactory {
    encryption_key: [u8; 32],
    cookie_secure: bool,
    session_duration_hours: u64,
    session_refresh_hours: u64,
    bind_session_to_ip: bool,
}

impl CookieFactory {
    /// Create a new cookie factory with the specified configuration
    #[must_use]
    pub fn new(
        encryption_key: [u8; 32],
        cookie_secure: bool,
        session_duration_hours: u64,
        session_refresh_hours: u64,
        bind_session_to_ip: bool,
    ) -> Self {
        Self {
            encryption_key,
            cookie_secure,
            session_duration_hours,
            session_refresh_hours,
            bind_session_to_ip,
        }
    }

    /// Generic method to create a cookie with encrypted data
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails
    pub fn create_cookie<T: Serialize>(
        &self,
        name: &str,
        data: Option<&T>,
        options: CookieOptions,
    ) -> Result<Cookie<'static>> {
        let value = match data {
            Some(data) => encrypt_data(data, &self.encryption_key)?,
            None => String::new(),
        };

        Ok(Cookie::build(name.to_owned(), value)
            .http_only(options.http_only)
            .secure(self.cookie_secure && options.secure)
            .same_site(options.same_site)
            .path(options.path)
            .max_age(options.max_age)
            .finish())
    }

    /// Create an encrypted session cookie from `VouchrsSession`
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails
    pub fn create_session_cookie(&self, session: &VouchrsSession) -> Result<Cookie> {
        self.create_cookie(
            COOKIE_NAME,
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
            COOKIE_NAME,
            Some(session),
            CookieOptions {
                same_site: actix_web::cookie::SameSite::Lax,
                max_age: actix_web::cookie::time::Duration::hours(refresh_duration),
                ..Default::default()
            },
        )
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
                COOKIE_NAME,
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

    /// Create an encrypted user data cookie from `VouchrsUserData`
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails
    pub fn create_user_cookie(&self, user_data: &VouchrsUserData) -> Result<Cookie> {
        self.create_cookie(
            USER_COOKIE_NAME,
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

    /// Create a temporary cookie for storing OAuth state during the OAuth flow
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails
    pub fn create_temporary_state_cookie(
        &self,
        oauth_state: &OAuthState,
    ) -> Result<Cookie<'static>> {
        let cookie_name = OAUTH_STATE_COOKIE;
        let options = CookieOptions {
            same_site: actix_web::cookie::SameSite::Lax,
            max_age: actix_web::cookie::time::Duration::minutes(10), // Short-lived for OAuth flow
            ..Default::default()
        };

        let cookie = self.create_cookie(cookie_name, Some(oauth_state), options)?;

        log::info!(
            "Creating temporary state cookie: secure={}, name={}, encrypted_len={}",
            self.cookie_secure,
            cookie_name,
            cookie.value().len()
        );

        Ok(cookie)
    }

    /// Create an expired cookie to clear the session
    #[must_use]
    pub fn create_expired_cookie(&self) -> Cookie<'static> {
        create_expired_cookie(COOKIE_NAME, self.cookie_secure)
    }

    /// Check if cookie refresh is enabled
    #[must_use]
    pub fn is_cookie_refresh_enabled(&self) -> bool {
        self.session_refresh_hours > 0
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
}

/// Helper function to extract cookie value from `HttpRequest`
///
/// # Errors
///
/// Returns an error if the specified cookie is not found in the request
pub fn extract_cookie_value(req: &HttpRequest, cookie_name: &str) -> Result<String> {
    req.cookie(cookie_name)
        .ok_or_else(|| anyhow!("Cookie not found: {cookie_name}"))
        .map(|cookie| cookie.value().to_string())
}

/// Create an expired cookie to clear a specific cookie
#[must_use]
pub fn create_expired_cookie(name: &str, secure: bool) -> Cookie<'static> {
    Cookie::build(name.to_owned(), "")
        .http_only(true)
        .secure(secure)
        .same_site(actix_web::cookie::SameSite::Lax)
        .path("/")
        .max_age(actix_web::cookie::time::Duration::seconds(-1))
        .finish()
}

/// Helper function to extract and log cookies from a request
pub fn log_cookies(req: &HttpRequest) {
    if let Ok(cookies) = req.cookies() {
        for cookie in cookies.iter() {
            log::info!(
                "Found cookie: name='{}', secure={:?}",
                cookie.name(),
                cookie.secure()
            );
        }
    }
}

/// Filter cookies, removing `vouchrs_session` cookie
#[must_use]
pub fn filter_vouchrs_cookies(cookie_str: &str) -> Option<String> {
    let filtered_cookies: Vec<&str> = cookie_str
        .split(';')
        .filter_map(|cookie| {
            let trimmed = cookie.trim();
            if trimmed.is_empty() || trimmed.starts_with(&format!("{COOKIE_NAME}=")) {
                None
            } else {
                Some(trimmed)
            }
        })
        .collect();

    if filtered_cookies.is_empty() {
        None
    } else {
        Some(filtered_cookies.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{constants::TEST_JWT_KEY, TestFixtures};

    #[test]
    fn test_filter_vouchrs_cookies() {
        // Test with single vouchrs_session cookie
        let cookies = "vouchrs_session=abc123";
        assert_eq!(filter_vouchrs_cookies(cookies), None);

        // Test with multiple cookies including vouchrs_session
        let cookies = "other_cookie=value; vouchrs_session=abc123; another_cookie=value2";
        assert_eq!(
            filter_vouchrs_cookies(cookies),
            Some("other_cookie=value; another_cookie=value2".to_string())
        );

        // Test with no vouchrs_session cookie
        let cookies = "cookie1=value1; cookie2=value2";
        assert_eq!(
            filter_vouchrs_cookies(cookies),
            Some("cookie1=value1; cookie2=value2".to_string())
        );

        // Test with empty string
        assert_eq!(filter_vouchrs_cookies(""), None);
    }

    #[test]
    fn test_create_expired_cookie() {
        let cookie = create_expired_cookie("test_cookie", true);
        assert_eq!(cookie.name(), "test_cookie");
        assert_eq!(cookie.value(), "");
        assert!(cookie.http_only().unwrap());
        assert!(cookie.secure().unwrap());
        assert_eq!(cookie.path().unwrap(), "/");
        assert!(cookie.max_age().unwrap().whole_seconds() < 0);
    }

    #[test]
    fn test_cookie_factory_creation() {
        let factory = CookieFactory::new(
            crate::utils::crypto::derive_encryption_key(TEST_JWT_KEY),
            false,
            24,
            2,
            false,
        );

        // Test session cookie creation
        let session = TestFixtures::oauth_session();
        let cookie = factory.create_session_cookie(&session).unwrap();
        assert_eq!(cookie.name(), COOKIE_NAME);
        assert!(!cookie.value().is_empty());

        // Test user cookie creation
        let user_data = TestFixtures::user_data();
        let user_cookie = factory.create_user_cookie(&user_data).unwrap();
        assert_eq!(user_cookie.name(), USER_COOKIE_NAME);
        assert!(!user_cookie.value().is_empty());
    }

    #[test]
    fn test_cookie_factory_refresh() {
        let factory_with_refresh = CookieFactory::new(
            crate::utils::crypto::derive_encryption_key(TEST_JWT_KEY),
            false,
            24,
            2, // 2 hour refresh
            false,
        );

        let factory_no_refresh = CookieFactory::new(
            crate::utils::crypto::derive_encryption_key(TEST_JWT_KEY),
            false,
            24,
            0, // No refresh
            false,
        );

        assert!(factory_with_refresh.is_cookie_refresh_enabled());
        assert!(!factory_no_refresh.is_cookie_refresh_enabled());

        let session = TestFixtures::oauth_session();
        let normal_cookie = factory_with_refresh
            .create_session_cookie(&session)
            .unwrap();
        let refreshed_cookie = factory_with_refresh
            .create_refreshed_session_cookie(&session)
            .unwrap();

        // Both should be valid cookies but may have different max_age
        assert_eq!(normal_cookie.name(), COOKIE_NAME);
        assert_eq!(refreshed_cookie.name(), COOKIE_NAME);
    }
}
