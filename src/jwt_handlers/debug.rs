// Debug handler for sessions
use crate::session::SessionManager;
use actix_web::{web, HttpRequest, HttpResponse, Result};
use log::{debug, error, info};

/// OAuth2 userinfo endpoint - returns user data from encrypted user cookie
pub async fn jwt_oauth_userinfo(
    req: HttpRequest,
    jwt_manager: web::Data<SessionManager>,
    _settings: web::Data<crate::settings::VouchrsSettings>,
) -> Result<HttpResponse> {
    use crate::utils::cookie_utils::USER_COOKIE_NAME;

    // Get the vouchrs_user cookie directly
    if let Some(cookie) = req.cookie(USER_COOKIE_NAME) {
        // Attempt to decrypt the cookie value
        match jwt_manager.decrypt_data::<crate::models::VouchrsUserData>(cookie.value()) {
            Ok(user_data) => {
                info!("Userinfo endpoint: returning raw user data for user: {}", user_data.email);
                
                // Return the complete user data as raw JSON
                Ok(HttpResponse::Ok().json(user_data))
            },
            Err(e) => {
                error!("Userinfo endpoint: Error decrypting user cookie: {}", e);
                Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "invalid_cookie", 
                    "error_description": "Failed to decrypt user cookie data",
                    "details": e.to_string()
                })))
            }
        }
    } else {
        debug!("Userinfo endpoint: No vouchrs_user cookie found");
        Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "no_user_data",
            "error_description": "No user data cookie found. Please authenticate first."
        })))
    }
}

pub async fn jwt_oauth_debug(
    req: HttpRequest,
    jwt_manager: web::Data<JwtSessionManager>,
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

    match jwt_manager.get_session_from_request(&req) {
        Ok(Some(session)) => {
            // Also try to get user data from user cookie
            let user_data = jwt_manager.get_user_data_from_request(&req)
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
            Ok(HttpResponse::Unauthorized().json(create_no_session_response(&req)))
        }
        Err(e) => {
            error!("Debug endpoint: Error retrieving session: {}", e);
            Ok(HttpResponse::Unauthorized().json(create_session_error_response(&req, &e)))
        }
    }
}

fn create_no_session_response(req: &HttpRequest) -> serde_json::Value {
    let raw_cookie_data = req.cookie("vouchrs_session").map(|cookie| {
        let cookie_value = cookie.value();
        serde_json::json!({
            "raw_encrypted_data": cookie_value,
            "cookie_length": cookie_value.len(),
            "cookie_preview": format!("{}...{}",
                &cookie_value[..std::cmp::min(50, cookie_value.len())],
                if cookie_value.len() > 100 {
                    &cookie_value[cookie_value.len()-20..]
                } else {
                    ""
                }
            ),
            "note": "Cookie found but session is invalid, expired, or failed to decrypt"
        })
    });

    serde_json::json!({
        "error": "No session",
        "message": "No valid session found",
        "cookie_analysis": {
            "decryption_successful": false,
            "session_cookie_found": raw_cookie_data.is_some(),
            "raw_cookie_data": raw_cookie_data,
            "possible_reasons": [
                "Session expired",
                "Cookie decryption failed (wrong key)",
                "Cookie corrupted or invalid format",
                "No session cookie present"
            ]
        },
        "debug_info": {
            "timestamp": chrono::Utc::now(),
            "has_cookies": req.cookies().map(|cookies| !cookies.is_empty()).unwrap_or(false)
        }
    })
}

fn create_session_error_response(req: &HttpRequest, error: &dyn std::fmt::Display) -> serde_json::Value {
    let raw_cookie_data = req.cookie("vouchrs_session").map(|cookie| {
        let cookie_value = cookie.value();
        serde_json::json!({
            "raw_encrypted_data": cookie_value,
            "cookie_length": cookie_value.len(),
            "cookie_preview": format!("{}...{}",
                &cookie_value[..std::cmp::min(50, cookie_value.len())],
                if cookie_value.len() > 100 {
                    &cookie_value[cookie_value.len()-20..]
                } else {
                    ""
                }
            ),
            "note": "Cookie found but decryption/validation failed"
        })
    });

    serde_json::json!({
        "error": "Session error",
        "message": format!("Error retrieving session: {}", error),
        "cookie_analysis": {
            "decryption_successful": false,
            "session_cookie_found": raw_cookie_data.is_some(),
            "raw_cookie_data": raw_cookie_data,
            "error_details": format!("{}", error)
        },
        "debug_info": {
            "timestamp": chrono::Utc::now()
        }
    })
}
