//! Session utility functions
//!
//! This module provides utility functions for session creation and management
//! that are used across different authentication methods (OAuth, Passkey, etc.)

use crate::oauth::OAuthState;
use crate::utils::crypto::decrypt_data;
use crate::utils::headers::{extract_user_agent_info, UserAgentInfo};
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
        .append_header(("Location", "/auth/sign_in?error=session_build_error"))
        .finish()
}

/// Parse OAuth state from received state parameter and retrieve stored state from cookie
/// This eliminates provider-specific branching logic by using the stored OAuth state
///
/// # Errors
///
/// Returns an error if:
/// - The received state does not match the stored CSRF token
/// - No stored state is found and encrypted state decryption fails
/// - The encrypted state format is invalid
pub fn get_state_from_callback(
    received_state: &str,
    session_manager: &crate::session::SessionManager,
    req: &actix_web::HttpRequest,
) -> Result<OAuthState, String> {
    log::debug!(
        "Received OAuth state parameter: length = {} characters",
        received_state.len()
    );

    // First, try to get the stored OAuth state from temporary cookie
    match session_manager.get_temporary_state_from_request(req) {
        Ok(Some(stored_state)) => {
            // For cookie-based state, verify the received state matches the stored CSRF token
            if stored_state.state == received_state {
                log::debug!(
                    "OAuth state verified: stored state matches received state for provider {}",
                    stored_state.provider
                );
                // Convert stored OAuth state to oauth::OAuthState
                Ok(OAuthState {
                    state: stored_state.state,
                    provider: stored_state.provider,
                    redirect_url: stored_state.redirect_url,
                })
            } else {
                Err(
                    "OAuth state mismatch: received state does not match stored CSRF token"
                        .to_string(),
                )
            }
        }
        Ok(None) => {
            // 🔒 SECURITY: Try to decrypt the received state parameter
            // This prevents tampering with provider name or redirect URL
            match decrypt_data::<OAuthState>(received_state, session_manager.encryption_key()) {
                Ok(decrypted_state) => {
                    log::debug!(
                        "Successfully decrypted OAuth state for provider: {}",
                        decrypted_state.provider
                    );
                    Ok(decrypted_state)
                }
                Err(e) => {
                    log::debug!("Failed to decrypt OAuth state: {e}");
                    Err("Invalid OAuth state: cannot decrypt state parameter".to_string())
                }
            }
        }
        Err(e) => {
            log::debug!("Failed to get stored OAuth state: {e}");
            Err("Invalid OAuth state: no stored state found".to_string())
        }
    }
}
