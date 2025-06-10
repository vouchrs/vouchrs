//! Session utility functions
//!
//! This module provides utility functions for session creation and management
//! that are used across different authentication methods (OAuth, Passkey, etc.)

use crate::utils::user_agent::{extract_user_agent_info, UserAgentInfo};
use actix_web::HttpResponse;

/// Extract client information from the request
///
/// Returns the client IP address and user agent information extracted
/// from the HTTP request headers.
pub fn extract_client_info(req: &actix_web::HttpRequest) -> (Option<String>, UserAgentInfo) {
    let client_ip = req
        .connection_info()
        .realip_remote_addr()
        .map(std::string::ToString::to_string);

    let user_agent_info = extract_user_agent_info(req);

    (client_ip, user_agent_info)
}

/// Create error response for session building failures
///
/// Creates a redirect response that clears any existing session cookies
/// and redirects to the sign-in page with an error parameter.
#[must_use]
pub fn create_error_response(
    session_manager: &crate::session::SessionManager,
    error_msg: &str,
) -> HttpResponse {
    use log::error;

    error!("{error_msg}");
    let clear_cookie = session_manager.create_expired_cookie();
    HttpResponse::Found()
        .cookie(clear_cookie)
        .append_header(("Location", "/oauth2/sign_in?error=session_build_error"))
        .finish()
}
