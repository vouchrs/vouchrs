//! Session validation utilities
//!
//! This module provides all session validation logic that `SessionManager` delegates to.
//! All functions are pure utilities that `SessionManager` calls to make validation decisions.

use crate::models::{VouchrsSession, VouchrsUserData};
use actix_web::HttpRequest;
use sha2::{Digest, Sha256};
use chrono::Utc;

/// Comprehensive session security validation
///
/// This performs all validation checks including client context, session expiration,
/// and any other security validations.
///
/// # Arguments
/// * `user_data` - The stored user data containing original client context
/// * `req` - The current HTTP request to validate against
/// * `session_expiration_hours` - Maximum session duration in hours
///
/// # Returns
/// * `Ok(true)` if all validations pass
/// * `Err(&'static str)` with error message if validation fails
///
/// # Errors
/// * Returns `Err("Client context validation failed")` if client fingerprint mismatch
/// * Returns `Err("Session has expired")` if session is beyond expiration window
pub fn validate_session_security(
    user_data: &VouchrsUserData,
    req: &HttpRequest,
    session_expiration_hours: u64,
) -> Result<bool, &'static str> {
    // Client context validation (session hijacking prevention)
    if !validate_client_context(user_data, req) {
        return Err("Client context validation failed");
    }

    // Session expiration validation
    let is_expired = is_session_expired(user_data, session_expiration_hours);
    if is_expired {
        return Err("Session has expired");
    }

    Ok(true)
}

/// Check if session has expired based on session start time
///
/// # Arguments
/// * `user_data` - User data containing session start timestamp
/// * `session_expiration_hours` - Maximum session duration in hours
///
/// # Returns
/// * `true` if session is expired or no session start time exists
/// * `false` if session is still valid
pub fn is_session_expired(user_data: &VouchrsUserData, session_expiration_hours: u64) -> bool {
    if let Some(session_start_timestamp) = user_data.session_start {
        let session_start_time = chrono::DateTime::from_timestamp(session_start_timestamp, 0)
            .unwrap_or_else(Utc::now);
        let now = Utc::now();
        let session_age = now.signed_duration_since(session_start_time);

        session_age.num_hours() >= i64::try_from(session_expiration_hours).unwrap_or(i64::MAX)
    } else {
        // If no session start time, consider it expired for safety
        true
    }
}

/// Validate IP binding for session security
///
/// Checks if the request IP matches the session's bound IP address.
///
/// # Arguments
/// * `session` - The session containing the bound IP
/// * `req` - The current HTTP request
///
/// # Returns
/// * `true` if IP matches or no IP binding is set
/// * `false` if IP validation fails
#[must_use]
pub fn validate_ip_binding(session: &VouchrsSession, req: &HttpRequest) -> bool {
    match (&session.client_ip, extract_client_ip(req)) {
        (Some(session_ip), Some(request_ip)) => session_ip == &request_ip,
        (None, _) => true, // No IP binding required
        (Some(_), None) => {
            log::warn!("Could not extract IP from request for validation");
            false
        }
    }
}

/// Check if OAuth session needs token refresh
///
/// Determines if an OAuth session's tokens are close to expiration and should be refreshed.
///
/// # Arguments
/// * `session` - The OAuth session to check
///
/// # Returns
/// * `true` if tokens should be refreshed (within 5-minute buffer)
/// * `false` if tokens are still valid
#[must_use]
pub fn needs_token_refresh(session: &VouchrsSession) -> bool {
    let now = chrono::Utc::now();
    let buffer_time = chrono::Duration::minutes(5);
    session.expires_at <= now + buffer_time
}

/// Check if session is expired based on `expires_at` timestamp
///
/// Simple time-based expiration check for `VouchrsSession` objects.
///
/// # Arguments
/// * `session` - The session to check
///
/// # Returns
/// * `true` if session is expired
/// * `false` if session is still valid
#[must_use]
pub fn is_session_time_expired(session: &VouchrsSession) -> bool {
    session.expires_at <= Utc::now()
}

/// Extract client IP from HTTP request
///
/// Helper function to extract client IP address from various headers.
///
/// # Arguments
/// * `req` - The HTTP request
///
/// # Returns
/// * `Some(String)` with the client IP if found
/// * `None` if no IP could be extracted
fn extract_client_ip(req: &HttpRequest) -> Option<String> {
    crate::session::utils::extract_client_info(req).0
}

/// Calculate SHA256 hash of client context for session hijacking prevention
///
/// # Arguments
/// * `client_ip` - Client IP address (optional)
/// * `user_agent` - User agent string (optional)
/// * `platform` - Platform string (optional)
///
/// Returns a SHA256 hash of the concatenated context data
#[must_use]
pub fn calculate_client_context_hash(
    client_ip: Option<&str>,
    user_agent: Option<&str>,
    platform: Option<&str>,
) -> String {
    let mut hasher = Sha256::new();

    // Include IP if available
    if let Some(ip) = client_ip {
        hasher.update(ip.as_bytes());
    }
    hasher.update(b"|"); // separator

    // Include user agent if available
    if let Some(ua) = user_agent {
        hasher.update(ua.as_bytes());
    }
    hasher.update(b"|"); // separator

    // Include platform if available
    if let Some(platform) = platform {
        hasher.update(platform.as_bytes());
    }

    format!("{:x}", hasher.finalize())
}

/// Validate client context against stored user data for session hijacking prevention
///
/// # Arguments
/// * `user_data` - The stored user data containing original client context
/// * `req` - The current HTTP request to validate against
///
/// Returns true if the client context matches the stored context
pub fn validate_client_context(user_data: &VouchrsUserData, req: &HttpRequest) -> bool {
    use crate::utils::headers::extract_user_agent_info;

    // Extract current client info from request
    let current_ip = req
        .connection_info()
        .realip_remote_addr()
        .map(std::string::ToString::to_string);
    let current_user_agent_info = extract_user_agent_info(req);

    // Calculate stored context hash
    let stored_hash = calculate_client_context_hash(
        user_data.client_ip.as_deref(),
        user_data.user_agent.as_deref(),
        user_data.platform.as_deref(),
    );

    // Calculate current context hash
    let current_hash = calculate_client_context_hash(
        current_ip.as_deref(),
        current_user_agent_info.user_agent.as_deref(),
        current_user_agent_info.platform.as_deref(),
    );

    stored_hash == current_hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixtures::TestFixtures, RequestBuilder};
    use chrono::{Duration, Utc};

    #[test]
    fn test_is_session_expired() {
        // Create user data with recent session start
        let mut user_data = TestFixtures::user_data();
        user_data.session_start = Some(Utc::now().timestamp());

        // Should not be expired within expiration window
        assert!(!is_session_expired(&user_data, 24));

        // Set session start to 25 hours ago
        user_data.session_start = Some((Utc::now() - Duration::hours(25)).timestamp());

        // Should be expired after 24 hour window
        assert!(is_session_expired(&user_data, 24));

        // User data without session start should be considered expired
        user_data.session_start = None;
        assert!(is_session_expired(&user_data, 24));
    }

    #[test]
    fn test_validate_ip_binding() {
        let req = RequestBuilder::new().with_client_ip("192.168.1.1").build();

        // Session with matching IP should pass
        let mut session = TestFixtures::oauth_session();
        session.client_ip = Some("192.168.1.1".to_string());
        assert!(validate_ip_binding(&session, &req));

        // Session with different IP should fail
        session.client_ip = Some("192.168.1.2".to_string());
        assert!(!validate_ip_binding(&session, &req));

        // Session without IP binding should pass
        session.client_ip = None;
        assert!(validate_ip_binding(&session, &req));
    }

    #[test]
    fn test_needs_token_refresh() {
        let mut session = TestFixtures::oauth_session();

        // Session expiring in 10 minutes should need refresh
        session.expires_at = Utc::now() + Duration::minutes(4);
        assert!(needs_token_refresh(&session));

        // Session expiring in 1 hour should not need refresh
        session.expires_at = Utc::now() + Duration::hours(1);
        assert!(!needs_token_refresh(&session));

        // Already expired session should need refresh
        session.expires_at = Utc::now() - Duration::minutes(10);
        assert!(needs_token_refresh(&session));
    }

    #[test]
    fn test_is_session_time_expired() {
        let mut session = TestFixtures::oauth_session();

        // Future expiration should not be expired
        session.expires_at = Utc::now() + Duration::hours(1);
        assert!(!is_session_time_expired(&session));

        // Past expiration should be expired
        session.expires_at = Utc::now() - Duration::hours(1);
        assert!(is_session_time_expired(&session));
    }

    #[test]
    fn test_validate_session_security() {
        use crate::testing::constants::{TEST_CLIENT_IP, TEST_USER_AGENT, TEST_PLATFORM};

        let user_data = TestFixtures::user_data();
        let req = RequestBuilder::new()
            .with_client_ip(TEST_CLIENT_IP)
            .user_agent(TEST_USER_AGENT)
            .header("x-platform", TEST_PLATFORM)
            .build();

        // Valid session should pass comprehensive validation
        let result = validate_session_security(&user_data, &req, 24);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}
