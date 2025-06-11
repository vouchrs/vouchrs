use crate::models::VouchrsUserData;
use actix_web::HttpRequest;
use sha2::{Digest, Sha256};

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
