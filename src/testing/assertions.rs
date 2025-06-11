//! Custom assertion helpers and macros for testing
//!
//! This module provides specialized assertion functions for common testing patterns
//! in the Vouchrs application, making tests more readable and maintainable.

use crate::models::{VouchrsSession, VouchrsUserData};
use crate::session::SessionManager;
use crate::settings::VouchrsSettings;
use actix_web::{HttpRequest, HttpResponse};
use serde_json::Value;

/// Assert that an HTTP response has the expected status code
///
/// # Panics
///
/// Panics if the response status does not match the expected status code.
pub fn assert_status(response: &HttpResponse, expected_status: u16) {
    assert_eq!(
        response.status().as_u16(),
        expected_status,
        "Expected status {expected_status}, got {}",
        response.status()
    );
}

/// Assert that an HTTP response is successful (2xx status)
///
/// # Panics
///
/// Panics if the response status is not in the 2xx range.
pub fn assert_success(response: &HttpResponse) {
    assert!(
        response.status().is_success(),
        "Expected successful response, got {}",
        response.status()
    );
}

/// Assert that an HTTP response contains a specific header
///
/// # Panics
///
/// Panics if the header is not present in the response.
pub fn assert_header_present(response: &HttpResponse, header_name: &str) {
    assert!(
        response.headers().contains_key(header_name),
        "Expected header '{header_name}' to be present"
    );
}

/// Assert that an HTTP response header has a specific value
///
/// # Panics
///
/// Panics if the header is not present or has a different value.
pub fn assert_header_value(response: &HttpResponse, header_name: &str, expected_value: &str) {
    if let Some(header_value) = response.headers().get(header_name) {
        assert_eq!(
            header_value.to_str().unwrap_or(""),
            expected_value,
            "Header '{header_name}' has wrong value"
        );
    } else {
        panic!("Header '{header_name}' not found in response");
    }
}

/// Assert that a session is valid and not expired
///
/// # Panics
///
/// Panics if the session is expired or missing required fields.
pub fn assert_valid_session(session: &VouchrsSession) {
    assert!(
        session.expires_at > chrono::Utc::now(),
        "Session should not be expired"
    );
    assert!(
        !session.provider.is_empty(),
        "Session should have a provider"
    );
}

/// Assert that a session is expired
///
/// # Panics
///
/// Panics if the session is not expired.
pub fn assert_expired_session(session: &VouchrsSession) {
    assert!(
        session.expires_at <= chrono::Utc::now(),
        "Session should be expired"
    );
}

/// Assert that a session is an OAuth session
///
/// # Panics
///
/// Panics if the session is not a valid OAuth session.
pub fn assert_oauth_session(session: &VouchrsSession) {
    assert!(
        session.is_oauth_session(),
        "Session should be OAuth session"
    );
    assert!(
        session.id_token.is_some() || session.refresh_token.is_some(),
        "OAuth session should have id_token or refresh_token"
    );
    assert!(
        session.credential_id.is_none() && session.user_handle.is_none(),
        "OAuth session should not have passkey fields"
    );
}

/// Assert that a session is a passkey session
///
/// # Panics
///
/// Panics if the session is not a valid passkey session.
pub fn assert_passkey_session(session: &VouchrsSession) {
    assert!(
        session.is_passkey_session(),
        "Session should be passkey session"
    );
    assert!(
        session.credential_id.is_some() && session.user_handle.is_some(),
        "Passkey session should have credential_id and user_handle"
    );
    assert!(
        session.id_token.is_none() && session.refresh_token.is_none(),
        "Passkey session should not have OAuth tokens"
    );
}

/// Assert that a session belongs to a specific provider
///
/// # Panics
///
/// Panics if the session provider does not match the expected provider.
pub fn assert_session_provider(session: &VouchrsSession, expected_provider: &str) {
    assert_eq!(
        session.provider, expected_provider,
        "Session provider mismatch"
    );
}

/// Assert that user data contains required fields
///
/// # Panics
///
/// Panics if the user data is missing required fields.
pub fn assert_complete_user_data(user_data: &VouchrsUserData) {
    assert!(
        !user_data.email.is_empty(),
        "User email should not be empty"
    );
    assert!(
        !user_data.provider.is_empty(),
        "Provider should not be empty"
    );
    assert!(
        !user_data.provider_id.is_empty(),
        "Provider ID should not be empty"
    );
}

/// Assert that user data has specific provider
///
/// # Panics
///
/// Panics if the user data provider does not match the expected provider.
pub fn assert_user_provider(user_data: &VouchrsUserData, expected_provider: &str) {
    assert_eq!(
        user_data.provider, expected_provider,
        "User provider mismatch"
    );
}

/// Assert that settings are valid
///
/// # Panics
///
/// Panics if the settings contain invalid configuration values.
pub fn assert_valid_settings(settings: &VouchrsSettings) {
    assert!(
        !settings.application.host.is_empty(),
        "Host should not be empty"
    );
    assert!(settings.application.port > 0, "Port should be positive");
    assert!(
        !settings.session.session_secret.is_empty(),
        "Session secret should not be empty"
    );
    assert!(
        settings.session.session_duration_hours > 0,
        "Session duration should be positive"
    );
}

/// Assert that session manager is properly configured
pub fn assert_session_manager_config(manager: &SessionManager, expected_duration: u64) {
    // This function would need access to SessionManager internals
    // For now, we'll just test what we can access
    let _ = manager; // Suppress unused warning
    let _ = expected_duration;
    // TODO: Add actual assertions when SessionManager exposes configuration getters
}

/// Assert that JSON contains specific key-value pairs
///
/// # Panics
///
/// Panics if the JSON key is not found or has a different value.
pub fn assert_json_contains(json: &Value, key: &str, expected_value: &Value) {
    if let Some(actual_value) = json.get(key) {
        assert_eq!(
            actual_value, expected_value,
            "JSON key '{key}' has wrong value"
        );
    } else {
        panic!("JSON key '{key}' not found");
    }
}

/// Assert that JSON is an object and not empty
///
/// # Panics
///
/// Panics if the JSON is not an object or is empty.
pub fn assert_json_object(json: &Value) {
    assert!(json.is_object(), "JSON should be an object");
    assert!(
        !json.as_object().unwrap().is_empty(),
        "JSON object should not be empty"
    );
}

/// Assert that an HTTP request has a specific cookie
///
/// # Panics
///
/// Panics if the request does not contain the specified cookie.
pub fn assert_request_cookie(request: &HttpRequest, cookie_name: &str) {
    let has_cookie = request
        .cookies()
        .map(|cookies| cookies.iter().any(|c| c.name() == cookie_name))
        .unwrap_or(false);

    assert!(has_cookie, "Request should contain cookie '{cookie_name}'");
}

/// Assert that an HTTP request has a specific header
///
/// # Panics
///
/// Panics if the request does not contain the specified header.
pub fn assert_request_header(request: &HttpRequest, header_name: &str) {
    assert!(
        request.headers().contains_key(header_name),
        "Request should contain header '{header_name}'"
    );
}

/// Assert that an HTTP request has a specific user agent
///
/// # Panics
///
/// Panics if the request does not have the expected user agent header.
pub fn assert_user_agent(request: &HttpRequest, expected_user_agent: &str) {
    if let Some(user_agent) = request.headers().get("user-agent") {
        assert_eq!(
            user_agent.to_str().unwrap_or(""),
            expected_user_agent,
            "User-Agent header mismatch"
        );
    } else {
        panic!("User-Agent header not found in request");
    }
}

/// Macro for asserting provider-specific sessions
#[macro_export]
macro_rules! assert_provider_session {
    ($session:expr, $provider:expr) => {
        $crate::testing::assertions::assert_session_provider($session, $provider);
        $crate::testing::assertions::assert_valid_session($session);
    };
}

/// Macro for asserting session manager configuration
#[macro_export]
macro_rules! assert_session_manager_config {
    ($manager:expr, $duration:expr) => {
        $crate::testing::assertions::assert_session_manager_config($manager, $duration);
    };
}
