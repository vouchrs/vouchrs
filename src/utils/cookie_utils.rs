use actix_web::{cookie::Cookie, HttpRequest};
use anyhow::{Result, anyhow};
use log;

/// Common cookie names used across the application
pub const COOKIE_NAME: &str = "vouchrs_session";
pub const USER_COOKIE_NAME: &str = "vouchrs_user";
pub const OAUTH_STATE_COOKIE: &str = "vouchr_oauth_state";

/// Trait for converting objects to cookies
pub trait ToCookie<T> {
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

/// Helper function to extract cookie value from HttpRequest
pub fn extract_cookie_value(req: &HttpRequest, cookie_name: &str) -> Result<String> {
    req.cookie(cookie_name)
        .ok_or_else(|| anyhow!("Cookie not found: {}", cookie_name))
        .map(|cookie| cookie.value().to_string())
}

/// Create an expired cookie to clear a specific cookie
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
            log::info!("Found cookie: name='{}', secure={:?}", cookie.name(), cookie.secure());
        }
    }
}
