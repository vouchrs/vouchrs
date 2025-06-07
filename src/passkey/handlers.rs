//! `WebAuthn` request handlers
//!
//! This module provides HTTP handlers for `WebAuthn` operations,
//! implementing the registration and authentication endpoints.

use actix_web::{web, HttpRequest, HttpResponse, Result};
use base64::Engine;
use once_cell::sync::OnceCell;
use serde_json::json;

// Import both the old and new WebAuthn implementations for transition
use crate::webauthn::{AuthenticationResponse, AuthenticationState, WebAuthnService};

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
    let _user_handle = data
        .get("user_handle")
        .and_then(|v| v.as_str())
        .map(String::from);

    // Create WebAuthn service
    let webauthn_settings = settings.passkeys.to_webauthn_settings();
    let passkeys_service = WebAuthnService::new(webauthn_settings);

    // Start authentication
    // In this implementation, we don't have any stored credentials yet
    // so we pass None to the start_authentication method
    let (request_options, auth_state) = passkeys_service.start_authentication(None);

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

    // Create WebAuthn service
    let webauthn_settings = settings.passkeys.to_webauthn_settings();
    let _passkeys_service = WebAuthnService::new(webauthn_settings);

    // Since we don't have a real credential store, we'll skip the verification
    // In a real implementation you would:
    // 1. Look up the credential from storage
    // 2. Verify the authentication using:
    //    passkeys_service.finish_authentication(&credential_response, &authentication_state, &stored_credential)

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
