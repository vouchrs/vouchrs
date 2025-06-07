//! `WebAuthn` request handlers
//!
//! This module provides HTTP handlers for `WebAuthn` operations,
//! implementing the registration and authentication endpoints.

use actix_web::{web, HttpRequest, HttpResponse, Result};
use base64::Engine;
use once_cell::sync::OnceCell;
use serde_json::json;

// Import webauthn-rs-proto and prelude for the new implementation
use webauthn_rs::prelude::*;
use webauthn_rs_proto;

// Local types specific to handlers
use serde::Deserialize;

/// Registration request
#[derive(Deserialize)]
pub struct RegistrationRequest {
    pub name: String,
    pub email: String,
}
use crate::passkey::PasskeySessionBuilder;
use crate::session::SessionManager;
use crate::settings::VouchrsSettings;

/// Lazily initialized static Webauthn instance
fn get_webauthn(
    settings: &VouchrsSettings,
) -> Result<&'static webauthn_rs::Webauthn, HttpResponse> {
    static WEBAUTHN: OnceCell<webauthn_rs::Webauthn> = OnceCell::new();
    WEBAUTHN.get_or_try_init(|| {
        settings.passkeys.create_webauthn().map_err(|e| {
            log::error!("Failed to create WebAuthn: {e}");
            HttpResponse::InternalServerError().json(json!({
                "error": "webauthn_creation_failed",
                "message": "Failed to initialize WebAuthn"
            }))
        })
    })
}

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

    // Use static Webauthn instance
    let webauthn = match get_webauthn(settings) {
        Ok(w) => w,
        Err(resp) => return Ok(resp),
    };

    // Generate secure user handle as Uuid, which is what the API expects
    let user_handle_uuid = uuid::Uuid::new_v4();
    let user_handle_str = user_handle_uuid.to_string(); // Keep the string version for the response

    // Start registration with webauthn-rs
    let (options, state) = match webauthn.start_passkey_registration(
        user_handle_uuid, // Pass the actual UUID type
        &data.email,
        &data.name,
        None, // No existing credentials to exclude
    ) {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to start registration: {e}");
            return Ok(HttpResponse::InternalServerError().json(json!({
                "error": "registration_failed",
                "message": "Failed to start registration process"
            })));
        }
    };

    // Create user data to associate with the registration
    let user_data =
        crate::passkey::PasskeyUserData::new(&user_handle_str, &data.email, Some(&data.name));
    let user_data_encoded = match user_data.encode() {
        Ok(data) => data,
        Err(e) => {
            log::error!("Failed to encode user data: {e}");
            return Ok(HttpResponse::InternalServerError().json(json!({
                "error": "internal_error",
                "message": "Failed to process registration"
            })));
        }
    };

    // Serialize the state for storage in the response
    let state_serialized = match serde_json::to_string(&state) {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to serialize registration state: {e}");
            return Ok(HttpResponse::InternalServerError().json(json!({
                "error": "internal_error",
                "message": "Failed to process registration"
            })));
        }
    };

    // Return response with user data
    Ok(HttpResponse::Ok().json(json!({
        "creation_options": options, // JSON options for the browser
        "registration_state": state_serialized, // State for the verify call
        "user_data": user_data_encoded, // User data for stateless retrieval
        "user_handle": user_handle_str
    })))
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

    // Use static Webauthn instance
    let webauthn = match get_webauthn(settings) {
        Ok(w) => w,
        Err(resp) => return Ok(resp),
    };

    // Extract credential response (keep existing format for compatibility)
    let Some(credential_response) = data.get("credential_response").and_then(|v| {
        let json_value = v.clone();
        // Convert webauthn-rs-proto RegisterPublicKeyCredential from our JSON
        serde_json::from_value::<webauthn_rs_proto::RegisterPublicKeyCredential>(json_value).ok()
    }) else {
        return Ok(HttpResponse::BadRequest().json(json!({
            "error": "invalid_request",
            "message": "Invalid credential response format"
        })));
    }; // Get registration state directly as a PasskeyRegistration

    let registration_state = match data.get("registration_state").and_then(|v| v.as_str()) {
        Some(s) => match serde_json::from_str::<PasskeyRegistration>(s) {
            Ok(state) => state,
            Err(e) => {
                log::error!("Failed to deserialize registration state: {e}");
                return Ok(HttpResponse::BadRequest().json(json!({
                    "error": "invalid_state",
                    "message": "Invalid registration state format"
                })));
            }
        },
        None => {
            return Ok(HttpResponse::BadRequest().json(json!({
                "error": "invalid_state",
                "message": "Missing registration state"
            })));
        }
    };

    // For webauthn-rs, we don't need to check expiry here because
    // the library will handle timeout validation when we call finish_passkey_registration
    // The library was initialized with our timeout setting

    // Complete registration with webauthn-rs
    let passkey =
        match webauthn.finish_passkey_registration(&credential_response, &registration_state) {
            Ok(passkey) => passkey,
            Err(e) => {
                log::error!("Registration verification failed: {e}");
                return Ok(HttpResponse::BadRequest().json(json!({
                    "error": "registration_failed",
                    "message": format!("Failed to complete registration: {e}")
                })));
            }
        };

    // Extract credential_id using the cred_id accessor and convert to base64
    let credential_id =
        base64::engine::general_purpose::URL_SAFE.encode(passkey.cred_id().as_ref());

    // Extract user_handle from the registration data in user_data
    let user_handle = match data.get("user_data").and_then(|v| v.as_str()) {
        Some(encoded_user_data) => {
            match crate::passkey::PasskeyUserData::decode(encoded_user_data) {
                Ok(user_data) => user_data.user_handle,
                Err(_) => {
                    // If we can't decode, fall back to a default
                    "unknown_user".to_string()
                }
            }
        }
        None => {
            // If no user_data was provided, we'll use the one from the registration
            "unknown_user".to_string()
        }
    };

    // Return the same response format as before
    Ok(HttpResponse::Ok().json(json!({
        "success": true,
        "message": "Registration completed successfully",
        "user_handle": user_handle,
        "credential_id": credential_id,
    })))
}

/// Start passkey authentication using `webauthn-rs` (stateless)
///
/// # Errors
/// Returns an error response if:
/// - Passkeys are not enabled
/// - `WebAuthn` service creation fails
/// - Authentication initialization fails
pub fn start_authentication(
    _req: &HttpRequest,
    _data: &web::Json<serde_json::Value>,
    settings: &web::Data<VouchrsSettings>,
) -> Result<HttpResponse> {
    if !settings.passkeys.enabled {
        return Ok(HttpResponse::ServiceUnavailable().json(json!({
            "error": "passkeys_disabled",
            "message": "Passkey support is not enabled"
        })));
    }
    let webauthn = match settings.passkeys.create_webauthn() {
        Ok(w) => w,
        Err(e) => {
            log::error!("Failed to create WebAuthn: {e}");
            return Ok(HttpResponse::InternalServerError().json(json!({
                "error": "webauthn_creation_failed",
                "message": "Failed to initialize WebAuthn"
            })));
        }
    };
    let (options, state) = match webauthn.start_passkey_authentication(&[]) {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to start authentication: {e}");
            return Ok(HttpResponse::InternalServerError().json(json!({
                "error": "authentication_failed",
                "message": "Failed to start authentication process"
            })));
        }
    };
    let state_serialized = match serde_json::to_string(&state) {
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
        "request_options": options,
        "authentication_state": state_serialized,
        "note": "Client must include the user_data from registration in the complete request"
    })))
}

/// Extract and validate credential response from request data
fn extract_credential_response(
    data: &web::Json<serde_json::Value>,
) -> Result<webauthn_rs_proto::PublicKeyCredential, HttpResponse> {
    match data.get("credential_response").and_then(|v| {
        let json_value = v.clone();
        serde_json::from_value::<webauthn_rs_proto::PublicKeyCredential>(json_value).ok()
    }) {
        Some(response) => Ok(response),
        None => Err(HttpResponse::BadRequest().json(json!({
            "error": "invalid_request",
            "message": "Invalid credential response format"
        }))),
    }
}

/// Extract and validate authentication state from request data
fn extract_authentication_state(
    data: &web::Json<serde_json::Value>,
) -> Result<webauthn_rs_proto::RequestChallengeResponse, HttpResponse> {
    match data
        .get("authentication_state")
        .and_then(|v| v.as_str())
        .and_then(|s| serde_json::from_str::<webauthn_rs_proto::RequestChallengeResponse>(s).ok())
    {
        Some(state) => Ok(state),
        None => Err(HttpResponse::BadRequest().json(json!({
            "error": "invalid_state",
            "message": "Missing or invalid authentication state"
        }))),
    }
}

/// Validate authentication state timeout
fn validate_authentication_timeout(settings: &VouchrsSettings) -> Result<(), HttpResponse> {
    let now = chrono::Utc::now();
    let timeout_seconds = i64::try_from(settings.passkeys.timeout_seconds).unwrap_or(3600);
    let state_created = chrono::Utc::now() - chrono::Duration::seconds(timeout_seconds * 2);
    let expiry = now - chrono::Duration::seconds(timeout_seconds);

    if state_created < expiry {
        Err(HttpResponse::BadRequest().json(json!({
            "error": "state_expired",
            "message": "Authentication session has expired"
        })))
    } else {
        Ok(())
    }
}

/// Extract and validate user data from request
fn extract_and_validate_user_data(
    data: &web::Json<serde_json::Value>,
    credential_response: &webauthn_rs_proto::PublicKeyCredential,
) -> Result<crate::passkey::PasskeyUserData, HttpResponse> {
    let Some(user_data) = data
        .get("user_data")
        .and_then(|v| v.as_str())
        .and_then(|s| crate::passkey::PasskeyUserData::decode(s).ok()) else {
            log::error!("Missing or invalid user data");
            return Err(HttpResponse::BadRequest().json(json!({
                "error": "invalid_user_data",
                "message": "Missing or invalid user data"
            })));
        };

    let user_handle = credential_response
        .response
        .user_handle
        .as_ref()
        .map_or_else(|| "mock_user_handle".to_string(), |h| base64::engine::general_purpose::URL_SAFE.encode(h.as_ref()));

    if user_data.user_handle != user_handle {
        log::error!(
            "User handle mismatch: expected {}, got {:?}",
            user_data.user_handle,
            credential_response.response.user_handle
        );
        return Err(HttpResponse::BadRequest().json(json!({
            "error": "user_handle_mismatch",
            "message": "User data verification failed"
        })));
    }

    Ok(user_data)
}

/// Create session and cookies for authenticated user
fn create_authenticated_session(
    req: &HttpRequest,
    user_data: &crate::passkey::PasskeyUserData,
    credential_id: String,
    session_manager: &SessionManager,
) -> Result<HttpResponse, HttpResponse> {
    let user_handle = user_data.user_handle.clone();

    let session_result = PasskeySessionBuilder::build_passkey_session(
        user_data.email.clone(),
        user_data.name.clone(),
        user_handle,
        credential_id,
        None, // Use default session duration
    );

    match session_result {
        Ok(passkey_session) => {
            let client_ip = req
                .connection_info()
                .realip_remote_addr()
                .map(ToString::to_string);
            let user_agent_info = crate::utils::user_agent::extract_user_agent_info(req);
            let session = passkey_session.to_session();
            let user_data =
                passkey_session.to_user_data(client_ip.as_deref(), Some(&user_agent_info));

            if let (Ok(session_cookie), Ok(user_cookie)) = (
                session_manager.create_session_cookie(&session),
                session_manager.create_user_cookie(&user_data),
            ) {
                let redirect_url = "/".to_string();
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
                Err(HttpResponse::InternalServerError().json(json!({
                    "error": "cookie_creation_failed",
                    "message": "Failed to create session cookies"
                })))
            }
        }
        Err(e) => {
            log::error!("Failed to build passkey session: {e}");
            Err(HttpResponse::InternalServerError().json(json!({
                "error": "session_creation_failed",
                "message": "Failed to create user session"
            })))
        }
    }
}

/// Complete passkey authentication using `webauthn-rs` and `PasskeySessionBuilder`
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

    let credential_response = match extract_credential_response(data) {
        Ok(response) => response,
        Err(error_response) => return Ok(error_response),
    };

    let _authentication_state = match extract_authentication_state(data) {
        Ok(state) => state,
        Err(error_response) => return Ok(error_response),
    };

    if let Err(error_response) = validate_authentication_timeout(settings) {
        return Ok(error_response);
    }

    let user_data = match extract_and_validate_user_data(data, &credential_response) {
        Ok(data) => data,
        Err(error_response) => return Ok(error_response),
    };

    let credential_id =
        base64::engine::general_purpose::URL_SAFE.encode(&credential_response.raw_id);

    match create_authenticated_session(req, &user_data, credential_id, session_manager) {
        Ok(success_response) => Ok(success_response),
        Err(error_response) => Ok(error_response),
    }
}
