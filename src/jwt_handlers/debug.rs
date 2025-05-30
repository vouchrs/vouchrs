// Debug handler for JWT sessions
use crate::jwt_session::JwtSessionManager;
use actix_web::{web, HttpRequest, HttpResponse, Result};
use log::{debug, error, info};

/// OAuth2 userinfo endpoint - returns access_token JWT claims in JSON format
pub async fn jwt_oauth_userinfo(
    req: HttpRequest,
    jwt_manager: web::Data<JwtSessionManager>,
    _settings: web::Data<crate::settings::VouchrsSettings>,
) -> Result<HttpResponse> {
    // Get session from request
    match jwt_manager.get_session_from_request(&req) {
        Ok(Some(session)) => {
            // Check if we have an access_token in the session
            match &session.access_token {
                Some(access_token) => {
                    // Decode the JWT access token to get its claims
                    match super::helpers::decode_jwt_payload(access_token) {
                        Ok(claims) => {
                            info!("Userinfo endpoint: returning access token claims for user: {}", session.user_email);
                            Ok(HttpResponse::Ok().json(claims))
                        }
                        Err(e) => {
                            error!("Userinfo endpoint: Failed to decode access token JWT: {}", e);
                            Ok(crate::utils::response_builder::ResponseBuilder::json_response(
                                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                                serde_json::json!({
                                    "error": "invalid_token",
                                    "error_description": "Failed to decode access token"
                                })
                            ))
                        }
                    }
                }
                None => {
                    error!("Userinfo endpoint: No access token found in session for user: {}", session.user_email);
                    Ok(crate::utils::response_builder::ResponseBuilder::json_response(
                        actix_web::http::StatusCode::BAD_REQUEST,
                        serde_json::json!({
                            "error": "no_access_token",
                            "error_description": "No access token available in session"
                        })
                    ))
                }
            }
        }
        Ok(None) => {
            debug!("Userinfo endpoint: No valid JWT session found");
            Ok(crate::utils::response_builder::ResponseBuilder::json_response(
                actix_web::http::StatusCode::UNAUTHORIZED,
                serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "No valid session found. Please authenticate first."
                })
            ))
        }
        Err(e) => {
            error!("Userinfo endpoint: Error retrieving JWT session: {}", e);
            Ok(crate::utils::response_builder::ResponseBuilder::json_response(
                actix_web::http::StatusCode::UNAUTHORIZED,
                serde_json::json!({
                    "error": "invalid_request", 
                    "error_description": "Session validation failed"
                })
            ))
        }
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
        return Ok(crate::utils::response_builder::ResponseBuilder::forbidden_json(
            "Debug endpoint disabled. Set OAUTH_DEBUG_ENABLED=true to enable this endpoint"
        ));
    }

    match jwt_manager.get_session_from_request(&req) {
        Ok(Some(session)) => {
            info!(
                "Debug endpoint: returning complete session data for user: {}",
                session.user_email
            );

            let debug_response = serde_json::json!({
                "session_data": {
                    "user_email": session.user_email,
                    "user_name": session.user_name,
                    "provider": session.provider,
                    "provider_id": session.provider_id,
                    "created_at": session.created_at,
                    "expires_at": session.expires_at,
                    "id_token": session.id_token,
                    "refresh_token": session.refresh_token,
                    "access_token": session.access_token,
                },
                "debug_info": {
                    "cookie_name": "vouchrs_session",
                    "timestamp": chrono::Utc::now(),
                    "warning": "This endpoint exposes sensitive OAuth tokens and cookie data. Only use in development!"
                }
            });

            Ok(HttpResponse::Ok().json(debug_response))
        }
        Ok(None) => {
            debug!("Debug endpoint: No valid JWT session found");
            Ok(crate::utils::response_builder::ResponseBuilder::json_response(
                actix_web::http::StatusCode::UNAUTHORIZED,
                create_no_session_response(&req)
            ))
        }
        Err(e) => {
            error!("Debug endpoint: Error retrieving JWT session: {}", e);
            Ok(crate::utils::response_builder::ResponseBuilder::json_response(
                actix_web::http::StatusCode::UNAUTHORIZED,
                create_session_error_response(&req, &e)
            ))
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
        "message": "No valid JWT session found",
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
