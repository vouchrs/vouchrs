//! Session validation utilities
//!
//! This module provides all session validation logic that `SessionManager` delegates to.
//! All functions are pure utilities that `SessionManager` calls to make validation decisions.

use crate::models::{VouchrsSession, VouchrsUserData};
use actix_web::HttpRequest;
use chrono::Utc;
use sha2::{Digest, Sha256};

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

/// Enhanced comprehensive session security validation with configurable options
///
/// This function provides comprehensive validation with configurable options for different
/// security requirements.
///
/// # Arguments
/// * `user_data` - The stored user data containing original client context
/// * `req` - The current HTTP request to validate against
/// * `session_expiration_hours` - Maximum session duration in hours
/// * `require_ip_binding` - Whether to enforce IP binding validation
/// * `require_strict_context` - Whether to enforce strict client context validation
///
/// # Returns
/// * `Ok(true)` if all validations pass
/// * `Err(&'static str)` with error message if validation fails
///
/// # Errors
///
/// Returns an error if:
/// - Session has expired beyond the specified hours
/// - IP address validation fails when required
/// - Client context validation fails when required
/// - Unable to extract IP address from request when IP binding is required
pub fn validate_session_security_advanced(
    user_data: &VouchrsUserData,
    req: &HttpRequest,
    session_expiration_hours: u64,
    require_ip_binding: bool,
    require_strict_context: bool,
) -> Result<bool, &'static str> {
    // Session expiration validation (always performed)
    if is_session_expired(user_data, session_expiration_hours) {
        return Err("Session has expired");
    }

    // Optional IP binding validation
    if require_ip_binding {
        let current_ip = extract_client_ip(req);
        if let Some(stored_ip) = &user_data.client_ip {
            if let Some(request_ip) = current_ip {
                if stored_ip != &request_ip {
                    return Err("IP address validation failed");
                }
            } else {
                return Err("Unable to extract IP address from request");
            }
        }
    }

    // Optional strict client context validation
    if require_strict_context && !validate_client_context(user_data, req) {
        return Err("Client context validation failed");
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
        let session_start_time =
            chrono::DateTime::from_timestamp(session_start_timestamp, 0).unwrap_or_else(Utc::now);
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

/// Validate session only for client context (skip expiration checks)
///
/// Useful for cases where you want to validate session hijacking protection
/// without checking expiration times.
///
/// # Arguments
/// * `user_data` - The stored user data containing original client context
/// * `req` - The current HTTP request to validate against
///
/// # Returns
/// * `true` if client context matches
/// * `false` if validation fails
#[must_use]
pub fn validate_client_context_only(user_data: &VouchrsUserData, req: &HttpRequest) -> bool {
    validate_client_context(user_data, req)
}

/// Extract and validate user agent fingerprint for enhanced security
///
/// This function extracts user agent information and validates it against stored data
/// for enhanced session security.
///
/// # Arguments
/// * `stored_user_agent` - The stored user agent string
/// * `stored_platform` - The stored platform string
/// * `req` - The current HTTP request
///
/// # Returns
/// * `true` if user agent information matches
/// * `false` if validation fails
#[must_use]
pub fn validate_user_agent_fingerprint(
    stored_user_agent: Option<&str>,
    stored_platform: Option<&str>,
    req: &HttpRequest,
) -> bool {
    use crate::utils::headers::extract_user_agent_info;

    let current_info = extract_user_agent_info(req);

    // Compare user agent strings
    let ua_matches = match (stored_user_agent, &current_info.user_agent) {
        (Some(stored), Some(current)) => stored == current,
        (None, _) => true,        // If nothing stored, consider it a match
        (Some(_), None) => false, // If stored but not in request, fail
    };

    // Compare platform strings
    let platform_matches = match (stored_platform, &current_info.platform) {
        (Some(stored), Some(current)) => stored == current,
        (None, _) => true,        // If nothing stored, consider it a match
        (Some(_), None) => false, // If stored but not in request, fail
    };

    ua_matches && platform_matches
}

/// Create a secure session fingerprint for storage
///
/// Generates a secure fingerprint of the session context that can be stored
/// and later validated to detect session hijacking attempts.
///
/// # Arguments
/// * `req` - The HTTP request to extract context from
///
/// # Returns
/// * A secure hash string representing the session fingerprint
#[must_use]
pub fn create_session_fingerprint(req: &HttpRequest) -> String {
    let (client_ip, user_agent_info) = crate::session::utils::extract_client_info(req);

    calculate_client_context_hash(
        client_ip.as_deref(),
        user_agent_info.user_agent.as_deref(),
        user_agent_info.platform.as_deref(),
    )
}

/// Validate session fingerprint against stored fingerprint
///
/// Compares a stored session fingerprint with the current request context
/// to detect potential session hijacking.
///
/// # Arguments
/// * `stored_fingerprint` - The stored session fingerprint
/// * `req` - The current HTTP request
///
/// # Returns
/// * `true` if fingerprints match
/// * `false` if validation fails
#[must_use]
pub fn validate_session_fingerprint(stored_fingerprint: &str, req: &HttpRequest) -> bool {
    let current_fingerprint = create_session_fingerprint(req);
    stored_fingerprint == current_fingerprint
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
        use crate::testing::constants::{TEST_CLIENT_IP, TEST_PLATFORM, TEST_USER_AGENT};

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

    #[test]
    fn test_validate_session_security_advanced() {
        use crate::testing::constants::{TEST_CLIENT_IP, TEST_PLATFORM, TEST_USER_AGENT};

        let user_data = TestFixtures::user_data();
        let req = RequestBuilder::new()
            .with_client_ip(TEST_CLIENT_IP)
            .user_agent(TEST_USER_AGENT)
            .header("x-platform", TEST_PLATFORM)
            .build();

        // Valid session with all options enabled should pass
        let result = validate_session_security_advanced(&user_data, &req, 24, true, true);
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Test with IP binding disabled
        let result = validate_session_security_advanced(&user_data, &req, 24, false, true);
        assert!(result.is_ok());

        // Test with strict context disabled
        let result = validate_session_security_advanced(&user_data, &req, 24, true, false);
        assert!(result.is_ok());

        // Test with both disabled
        let result = validate_session_security_advanced(&user_data, &req, 24, false, false);
        assert!(result.is_ok());

        // Modify user data to simulate expired session
        let mut expired_user_data = user_data.clone();
        expired_user_data.session_start = Some((Utc::now() - Duration::hours(25)).timestamp());
        let result = validate_session_security_advanced(&expired_user_data, &req, 24, true, true);
        assert!(result.is_err());
        assert_eq!(result.err(), Some("Session has expired"));

        // Modify request IP to simulate IP validation failure
        let req_different_ip = RequestBuilder::new()
            .with_client_ip("192.168.1.2")
            .user_agent(TEST_USER_AGENT)
            .header("x-platform", TEST_PLATFORM)
            .build();
        let result =
            validate_session_security_advanced(&user_data, &req_different_ip, 24, true, true);
        assert!(result.is_err());
        assert_eq!(result.err(), Some("IP address validation failed"));

        // Session with no client IP should fail IP validation
        let req_no_ip = RequestBuilder::new()
            .user_agent(TEST_USER_AGENT)
            .header("x-platform", TEST_PLATFORM)
            .build();
        let result = validate_session_security_advanced(&user_data, &req_no_ip, 24, true, true);
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some("Unable to extract IP address from request")
        );
    }

    #[test]
    fn test_validate_client_context_only() {
        use crate::testing::constants::{TEST_CLIENT_IP, TEST_PLATFORM, TEST_USER_AGENT};

        let user_data = TestFixtures::user_data();
        let req = RequestBuilder::new()
            .with_client_ip(TEST_CLIENT_IP)
            .user_agent(TEST_USER_AGENT)
            .header("x-platform", TEST_PLATFORM)
            .build();

        // Valid context should pass
        assert!(validate_client_context_only(&user_data, &req));

        // Different IP should fail
        let req_different_ip = RequestBuilder::new()
            .with_client_ip("192.168.1.99")
            .user_agent(TEST_USER_AGENT)
            .header("x-platform", TEST_PLATFORM)
            .build();

        assert!(!validate_client_context_only(&user_data, &req_different_ip));
    }

    #[test]
    fn test_validate_user_agent_fingerprint() {
        use crate::testing::constants::{TEST_PLATFORM, TEST_USER_AGENT};

        let req = RequestBuilder::new()
            .user_agent(TEST_USER_AGENT)
            .header("x-platform", TEST_PLATFORM)
            .build();

        // Matching user agent and platform should pass
        assert!(validate_user_agent_fingerprint(
            Some(TEST_USER_AGENT),
            Some(TEST_PLATFORM),
            &req
        ));

        // Different user agent should fail
        assert!(!validate_user_agent_fingerprint(
            Some("Different User Agent"),
            Some(TEST_PLATFORM),
            &req
        ));

        // Different platform should fail
        assert!(!validate_user_agent_fingerprint(
            Some(TEST_USER_AGENT),
            Some("Different Platform"),
            &req
        ));

        // Both None should pass
        assert!(validate_user_agent_fingerprint(None, None, &req));
    }

    #[test]
    fn test_session_fingerprint_functions() {
        use crate::testing::constants::{TEST_CLIENT_IP, TEST_PLATFORM, TEST_USER_AGENT};

        let req = RequestBuilder::new()
            .with_client_ip(TEST_CLIENT_IP)
            .user_agent(TEST_USER_AGENT)
            .header("x-platform", TEST_PLATFORM)
            .build();

        // Create fingerprint
        let fingerprint = create_session_fingerprint(&req);
        assert!(!fingerprint.is_empty());

        // Validate same fingerprint
        assert!(validate_session_fingerprint(&fingerprint, &req));

        // Different request should have different fingerprint
        let req_different = RequestBuilder::new()
            .with_client_ip("192.168.1.99")
            .user_agent(TEST_USER_AGENT)
            .header("x-platform", TEST_PLATFORM)
            .build();

        assert!(!validate_session_fingerprint(&fingerprint, &req_different));
    }

    #[test]
    fn test_validate_session_fingerprint() {
        let req = RequestBuilder::new()
            .with_client_ip("192.168.1.1")
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3")
            .build();

        // Create fingerprint from request
        let fingerprint = create_session_fingerprint(&req);

        // Valid fingerprint should match
        assert!(validate_session_fingerprint(&fingerprint, &req));

        // Modify request IP (should not match)
        let req_different_ip = RequestBuilder::new()
            .with_client_ip("192.168.1.2")
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3")
            .build();
        assert!(!validate_session_fingerprint(
            &fingerprint,
            &req_different_ip
        ));

        // Modify user agent (should not match)
        let req_different_ua = RequestBuilder::new()
            .with_client_ip("192.168.1.1")
            .user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
            .build();
        assert!(!validate_session_fingerprint(
            &fingerprint,
            &req_different_ua
        ));

        // Modify platform via user agent (should not match)
        let req_different_platform = RequestBuilder::new()
            .with_client_ip("192.168.1.1")
            .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36")
            .build();
        assert!(!validate_session_fingerprint(
            &fingerprint,
            &req_different_platform
        ));
    }
}
