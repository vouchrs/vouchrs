//! `WebAuthn` request handlers
//!
//! This module provides HTTP handlers for `WebAuthn` operations,
//! implementing the registration and authentication endpoints.

use actix_web::{web, HttpRequest, HttpResponse, Result};
use serde_json::json;

use crate::passkey::types::{
    AuthenticationResponse, AuthenticationState, RegistrationRequest, RegistrationResponse,
    RegistrationState,
};
use crate::passkey::WebAuthnService;
use crate::passkey_session::PasskeySessionBuilder;
use crate::session::SessionManager;
use crate::settings::VouchrsSettings;

/// Start passkey registration
///
/// # Errors
/// Returns an error response if:
/// - Passkeys are not enabled
/// - Input validation fails
/// - `WebAuthn` service creation fails
/// - Registration initialization fails
pub fn start_registration(
    _req: &HttpRequest,
    data: &web::Json<RegistrationRequest>,
    settings: &web::Data<VouchrsSettings>,
) -> Result<HttpResponse> {
    if !settings.passkeys.enabled {
        return Ok(HttpResponse::ServiceUnavailable().json(json!({
            "error": "passkeys_disabled",
            "message": "Passkey support is not enabled"
        })));
    }

    // Validate input
    if data.name.trim().len() < 2 {
        return Ok(HttpResponse::BadRequest().json(json!({
            "error": "invalid_name",
            "message": "Name must be at least 2 characters"
        })));
    }

    if !data.email.contains('@') {
        return Ok(HttpResponse::BadRequest().json(json!({
            "error": "invalid_email",
            "message": "Invalid email format"
        })));
    }

    // Create WebAuthn service
    let passkeys_service = match WebAuthnService::new(settings.passkeys.clone()) {
        Ok(service) => service,
        Err(e) => {
            log::error!("Failed to create WebAuthn service: {e}");
            return Ok(HttpResponse::InternalServerError().json(json!({
                "error": "configuration_error",
                "message": "WebAuthn configuration error"
            })));
        }
    };

    // Generate secure user handle
    let user_handle = crate::passkey::generate_user_handle();

    // Start registration
    match passkeys_service.start_registration(&data.name, &data.email, &user_handle) {
        Ok((creation_options, registration_state)) => {
            // In a stateless architecture, we'd typically store the state
            // in a secure, signed cookie or include it in the response for the
            // client to pass back in the complete call

            // For this example, we'll include it in the response
            // In production, you might want to encrypt or sign this
            let state_serialized = match serde_json::to_string(&registration_state) {
                Ok(s) => s,
                Err(e) => {
                    log::error!("Failed to serialize registration state: {e}");
                    return Ok(HttpResponse::InternalServerError().json(json!({
                        "error": "internal_error",
                        "message": "Failed to process registration"
                    })));
                }
            };

            Ok(HttpResponse::Ok().json(json!({
                "creation_options": creation_options,
                "registration_state": state_serialized,
                "user_handle": user_handle
            })))
        }
        Err(e) => {
            log::error!("Registration start failed: {e}");
            Ok(HttpResponse::InternalServerError().json(json!({
                "error": "registration_failed",
                "message": format!("Failed to start registration: {e}")
            })))
        }
    }
}

/// Complete passkey registration
///
/// # Errors
/// Returns an error response if:
/// - Passkeys are not enabled
/// - Credential response format is invalid
/// - Registration state is missing or expired
/// - `WebAuthn` service creation fails
/// - Registration completion verification fails
pub fn complete_registration(
    _req: &HttpRequest,
    data: &web::Json<serde_json::Value>,
    settings: &web::Data<VouchrsSettings>,
) -> Result<HttpResponse> {
    if !settings.passkeys.enabled {
        return Ok(HttpResponse::ServiceUnavailable().json(json!({
            "error": "passkeys_disabled",
            "message": "Passkey support is not enabled"
        })));
    }

    // Extract required fields
    let credential_response: RegistrationResponse = match serde_json::from_value(
        data.get("credential_response")
            .cloned()
            .unwrap_or(json!(null)),
    ) {
        Ok(response) => response,
        Err(e) => {
            log::error!("Invalid credential response: {e}");
            return Ok(HttpResponse::BadRequest().json(json!({
                "error": "invalid_request",
                "message": "Invalid credential response format"
            })));
        }
    };

    // Get registration state
    let registration_state: RegistrationState = match data
        .get("registration_state")
        .and_then(|v| v.as_str())
        .and_then(|s| serde_json::from_str(s).ok())
    {
        Some(state) => state,
        None => {
            return Ok(HttpResponse::BadRequest().json(json!({
                "error": "invalid_state",
                "message": "Missing or invalid registration state"
            })));
        }
    };

    // Check if state has expired
    let now = chrono::Utc::now();
    // Use try_from to safely convert u64 to i64
    let timeout_seconds = i64::try_from(settings.passkeys.timeout_seconds).unwrap_or(3600); // Default to 1 hour if overflow would occur
    let expiry = registration_state.created_at + chrono::Duration::seconds(timeout_seconds);

    if now > expiry {
        return Ok(HttpResponse::BadRequest().json(json!({
            "error": "state_expired",
            "message": "Registration session has expired"
        })));
    }

    // Create WebAuthn service
    let passkeys_service = match WebAuthnService::new(settings.passkeys.clone()) {
        Ok(service) => service,
        Err(e) => {
            log::error!("Failed to create WebAuthn service: {e}");
            return Ok(HttpResponse::InternalServerError().json(json!({
                "error": "configuration_error",
                "message": "WebAuthn configuration error"
            })));
        }
    };

    // Complete registration
    match passkeys_service.complete_registration(&credential_response, &registration_state) {
        Ok(credential) => {
            // This is where upstream systems would store the credential
            // Since VouchRS is stateless, we'll just acknowledge successful registration
            // The upstream system needs to associate user_handle with the user account

            Ok(HttpResponse::Ok().json(json!({
                "success": true,
                "message": "Registration completed successfully",
                "user_handle": registration_state.user_handle,
                "credential_id": credential.credential_id,
            })))
        }
        Err(e) => {
            log::error!("Registration completion failed: {e}");
            Ok(HttpResponse::BadRequest().json(json!({
                "error": "registration_failed",
                "message": format!("Failed to complete registration: {e}")
            })))
        }
    }
}

/// Start passkey authentication
///
/// # Errors
/// Returns an error response if:
/// - Passkeys are not enabled
/// - `WebAuthn` service creation fails
/// - Authentication initialization fails
pub fn start_authentication(
    _req: &HttpRequest,
    data: &web::Json<serde_json::Value>,
    settings: &web::Data<VouchrsSettings>,
) -> Result<HttpResponse> {
    if !settings.passkeys.enabled {
        return Ok(HttpResponse::ServiceUnavailable().json(json!({
            "error": "passkeys_disabled",
            "message": "Passkey support is not enabled"
        })));
    }

    // Extract user handle if provided (optional)
    let user_handle = data
        .get("user_handle")
        .and_then(|v| v.as_str())
        .map(String::from);

    // Create WebAuthn service
    let passkeys_service = match WebAuthnService::new(settings.passkeys.clone()) {
        Ok(service) => service,
        Err(e) => {
            log::error!("Failed to create WebAuthn service: {e}");
            return Ok(HttpResponse::InternalServerError().json(json!({
                "error": "configuration_error",
                "message": "WebAuthn configuration error"
            })));
        }
    };

    // Start authentication
    match passkeys_service.start_authentication(
        user_handle.as_deref(),
        None, // No credential filtering
    ) {
        Ok((request_options, auth_state)) => {
            // Serialize authentication state
            let state_serialized = match serde_json::to_string(&auth_state) {
                Ok(s) => s,
                Err(e) => {
                    log::error!("Failed to serialize authentication state: {e}");
                    return Ok(HttpResponse::InternalServerError().json(json!({
                        "error": "internal_error",
                        "message": "Failed to process authentication"
                    })));
                }
            };

            Ok(HttpResponse::Ok().json(json!({
                "request_options": request_options,
                "authentication_state": state_serialized
            })))
        }
        Err(e) => {
            log::error!("Authentication start failed: {e}");
            Ok(HttpResponse::InternalServerError().json(json!({
                "error": "authentication_failed",
                "message": format!("Failed to start authentication: {e}")
            })))
        }
    }
}

/// Validate authentication state
///
/// # Errors
/// Returns an error response if:
/// - Authentication state is missing or invalid
/// - Authentication state has expired
fn validate_authentication_state(
    data: &web::Json<serde_json::Value>,
    settings: &web::Data<VouchrsSettings>,
) -> Result<(AuthenticationState, AuthenticationResponse), HttpResponse> {
    // Extract required fields
    let credential_response: AuthenticationResponse = match serde_json::from_value(
        data.get("credential_response")
            .cloned()
            .unwrap_or(json!(null)),
    ) {
        Ok(response) => response,
        Err(e) => {
            log::error!("Invalid credential response: {e}");
            return Err(HttpResponse::BadRequest().json(json!({
                "error": "invalid_request",
                "message": "Invalid credential response format"
            })));
        }
    };

    // Get authentication state
    let authentication_state: AuthenticationState = match data
        .get("authentication_state")
        .and_then(|v| v.as_str())
        .and_then(|s| serde_json::from_str(s).ok())
    {
        Some(state) => state,
        None => {
            return Err(HttpResponse::BadRequest().json(json!({
                "error": "invalid_state",
                "message": "Missing or invalid authentication state"
            })));
        }
    };

    // Check if state has expired
    let now = chrono::Utc::now();
    // Use try_from to safely convert u64 to i64
    let timeout_seconds = i64::try_from(settings.passkeys.timeout_seconds).unwrap_or(3600); // Default to 1 hour if overflow would occur
    let expiry = authentication_state.created_at + chrono::Duration::seconds(timeout_seconds);

    if now > expiry {
        return Err(HttpResponse::BadRequest().json(json!({
            "error": "state_expired",
            "message": "Authentication session has expired"
        })));
    }

    Ok((authentication_state, credential_response))
}

/// Complete passkey authentication
///
/// # Errors
/// Returns an error response if:
/// - Passkeys are not enabled
/// - Credential response format is invalid
/// - Authentication state is missing or expired
/// - Session creation fails
/// - Cookie creation fails
pub fn complete_authentication(
    req: &HttpRequest,
    data: &web::Json<serde_json::Value>,
    settings: &web::Data<VouchrsSettings>,
    session_manager: &web::Data<SessionManager>,
) -> Result<HttpResponse> {
    if !settings.passkeys.enabled {
        return Ok(HttpResponse::ServiceUnavailable().json(json!({
            "error": "passkeys_disabled",
            "message": "Passkey support is not enabled"
        })));
    }

    // Validate authentication state
    let (_authentication_state, credential_response) =
        match validate_authentication_state(data, settings) {
            Ok(validated) => validated,
            Err(response) => return Ok(response),
        };

    // This is where we would:
    // 1. Extract the credential ID from the response
    let credential_id = credential_response.id.clone();

    // 2. Lookup the credential from upstream storage
    // Since VouchRS is stateless, this would be handled by the upstream system
    // For demonstration, we'll create a mock credential

    // In a real implementation, this would be a call to an upstream API
    // or database to retrieve the stored credential and user information

    // For now, we'll mock a successful authentication
    // In a real implementation, this is where you'd verify the signature

    // Create a mock user for this example
    // In a real implementation, this data would come from your user store
    let user_email = "user@example.com";
    let user_name = "Test User";
    let user_handle = credential_response
        .response
        .user_handle
        .clone()
        .unwrap_or_else(|| "mock_user_handle".to_string());

    // Create session using the PasskeySessionBuilder
    let session_result = PasskeySessionBuilder::build_passkey_session(
        user_email.to_string(),
        Some(user_name.to_string()),
        user_handle.clone(),
        credential_id.clone(),
        None, // Use default session duration
    );

    match session_result {
        Ok(passkey_session) => {
            // Extract client IP and user agent
            let client_ip = req
                .connection_info()
                .realip_remote_addr()
                .map(ToString::to_string);
            let user_agent_info = crate::utils::user_agent::extract_user_agent_info(req);

            // Create session cookie
            let session = passkey_session.to_session();
            let user_data =
                passkey_session.to_user_data(client_ip.as_deref(), Some(&user_agent_info));

            // Create cookies using existing session manager
            if let (Ok(session_cookie), Ok(user_cookie)) = (
                session_manager.create_session_cookie(&session),
                session_manager.create_user_cookie(&user_data),
            ) {
                let redirect_url = "/".to_string(); // Use root as default redirect

                // Successful authentication with session cookies
                Ok(HttpResponse::Ok()
                    .cookie(session_cookie)
                    .cookie(user_cookie)
                    .json(json!({
                        "success": true,
                        "message": "Authentication successful",
                        "redirect_url": redirect_url,
                    })))
            } else {
                log::error!("Failed to create session cookies");
                Ok(HttpResponse::InternalServerError().json(json!({
                    "error": "cookie_creation_failed",
                    "message": "Failed to create session cookies"
                })))
            }
        }
        Err(e) => {
            log::error!("Failed to build passkey session: {e}");
            Ok(HttpResponse::InternalServerError().json(json!({
                "error": "session_creation_failed",
                "message": "Failed to create user session"
            })))
        }
    }
}
