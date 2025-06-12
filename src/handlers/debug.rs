// Debug handler for sessions
use crate::session::SessionManager;
use crate::utils::responses::ResponseBuilder;
use actix_web::{web, HttpRequest, HttpResponse, Result};
use log::{debug, error, info};

/// `OAuth2` userinfo endpoint - returns user data from encrypted user cookie
///
/// # Errors
/// Returns an error if session extraction fails or user data is invalid
pub async fn oauth_userinfo(
    req: HttpRequest,
    session_manager: web::Data<SessionManager>,
    _settings: web::Data<crate::settings::VouchrsSettings>,
) -> Result<HttpResponse> {
    use crate::session::cookie::USER_COOKIE_NAME;

    // Get the vouchrs_user cookie directly
    req.cookie(USER_COOKIE_NAME).map_or_else(
        || {
            debug!("Userinfo endpoint: No vouchrs_user cookie found");
            Ok(ResponseBuilder::unauthorized().build())
        },
        |cookie| match crate::utils::crypto::decrypt_data::<crate::models::VouchrsUserData>(
            cookie.value(),
            session_manager.encryption_key(),
        ) {
            Ok(user_data) => {
                info!(
                    "Userinfo endpoint: returning raw user data for user: {}",
                    user_data.email
                );

                // Return the complete user data as raw JSON
                Ok(HttpResponse::Ok().json(user_data))
            }
            Err(e) => {
                error!("Userinfo endpoint: Error decrypting user cookie: {e}");
                Ok(ResponseBuilder::unauthorized().build())
            }
        },
    )
}

/// Debug endpoint - returns debug information from session
///
/// # Errors
/// Returns an error if session extraction fails or debug data is invalid
pub async fn oauth_debug(
    req: HttpRequest,
    session_manager: web::Data<SessionManager>,
    _settings: web::Data<crate::settings::VouchrsSettings>,
) -> Result<HttpResponse> {
    // Check if debug mode is enabled via environment variable
    let debug_enabled = std::env::var("OAUTH_DEBUG_ENABLED")
        .unwrap_or_else(|_| "false".to_string())
        .to_lowercase()
        == "true";

    if !debug_enabled {
        error!("OAuth debug endpoint accessed but OAUTH_DEBUG_ENABLED is not set to true");
        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "error": "debug_disabled",
            "error_description": "Debug endpoint disabled. Set OAUTH_DEBUG_ENABLED=true to enable this endpoint"
        })));
    }

    match session_manager.get_session_from_request(&req) {
        Ok(Some(session)) => {
            // Also try to get user data from user cookie
            let user_data = session_manager
                .cookie_factory()
                .get_user_data_from_request(&req)
                .unwrap_or(None);

            let debug_response = serde_json::json!({
                "session_data": {
                    "provider": session.provider,
                    "expires_at": session.expires_at,
                    "id_token": session.id_token,
                    "refresh_token": session.refresh_token,
                },
                "debug_info": {
                    "session_cookie_name": "vouchrs_session",
                    "user_cookie_name": "vouchrs_user",
                    "user_cookie": user_data,
                    "timestamp": chrono::Utc::now(),
                }
            });

            Ok(HttpResponse::Ok().json(debug_response))
        }
        Ok(None) => {
            debug!("Debug endpoint: No valid session found");
            Ok(ResponseBuilder::unauthorized().build())
        }
        Err(e) => {
            error!("Debug endpoint: Error retrieving session: {e}");
            Ok(ResponseBuilder::unauthorized().build())
        }
    }
}
