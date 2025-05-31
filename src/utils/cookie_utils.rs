use actix_web::{cookie::Cookie, HttpRequest};
use anyhow::{anyhow, Result};
use log;

/// Common cookie names used across the application
pub const COOKIE_NAME: &str = "vouchrs_session";
pub const USER_COOKIE_NAME: &str = "vouchrs_user";
pub const OAUTH_STATE_COOKIE: &str = "vouchr_oauth_state";

/// Trait for converting objects to cookies
pub trait ToCookie<T> {
    /// Convert self to a cookie with provided name using `SessionManager` for encryption
    /// 
    /// # Errors
    /// 
    /// Returns an error if the cookie creation fails (e.g., encryption failure)
    fn to_cookie(&self, manager: &T) -> Result<Cookie<'static>>;
}

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
        .filter(|cookie| {
            let trimmed = cookie.trim();
            !trimmed.starts_with(&format!("{COOKIE_NAME}="))
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
}
