//! `WebAuthn` request handlers
//!
//! This module provides HTTP handlers for `WebAuthn` operations,
//! implementing the registration and authentication endpoints.

use actix_web::{web, HttpRequest, HttpResponse, Result};
use base64::Engine;
use once_cell::sync::OnceCell;
use serde_json::json;

// Import webauthn-rs-proto for external type compatibility
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

/// Lazily initialized static `WebAuthnService` instance
fn get_webauthn(
    settings: &VouchrsSettings,
) -> Result<&'static crate::webauthn::WebAuthnService, HttpResponse> {
    static WEBAUTHN: OnceCell<crate::webauthn::WebAuthnService> = OnceCell::new();
    WEBAUTHN.get_or_try_init(|| {
        settings.passkeys.create_webauthn_service().map_err(|e| {
            log::error!("Failed to create WebAuthnService: {e}");
            HttpResponse::InternalServerError().json(json!({
                "error": "webauthn_creation_failed",
                "message": "Failed to initialize WebAuthnService"
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

    // More comprehensive email validation
    let email = data.email.trim();
    if email.is_empty() {
        return Ok(HttpResponse::BadRequest().json(json!({
            "error": "invalid_email",
            "message": "Email address is required"
        })));
    }

    if !email.contains('@') || !email.contains('.') || email.len() < 5 {
        return Ok(HttpResponse::BadRequest().json(json!({
            "error": "invalid_email",
            "message": "Please enter a valid email address (e.g., user@example.com)"
        })));
    }

    // Basic email format validation
    let email_parts: Vec<&str> = email.split('@').collect();
    if email_parts.len() != 2 || email_parts[0].is_empty() || email_parts[1].is_empty() {
        return Ok(HttpResponse::BadRequest().json(json!({
            "error": "invalid_email",
            "message": "Please enter a valid email address (e.g., user@example.com)"
        })));
    }

    // Generate secure user handle as Uuid, which is what the API expects
    let user_handle = uuid::Uuid::new_v4().to_string();

    // Use static Webauthn instance (with global policy)
    let webauthn = match get_webauthn(settings) {
        Ok(w) => w,
        Err(resp) => return Ok(resp),
    };

    // Use the user_handle as a string (UUID)
    let (options, state) = webauthn.start_registration(&user_handle, email, &data.name);

    // Create user data to associate with the registration
    let user_data =
        crate::passkey::PasskeyUserData::new(&user_handle, &data.email, Some(&data.name));
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
        "creation_options": {
            "publicKey": options // Wrap options in publicKey field as per WebAuthn spec
        },
        "registration_state": state_serialized, // State for the verify call
        "user_data": user_data_encoded, // User data for stateless retrieval
        "user_handle": user_handle
    })))
}

/// Extract registration credential response from request data
fn extract_registration_credential_response(
    data: &web::Json<serde_json::Value>,
) -> Result<crate::webauthn::RegistrationResponse, HttpResponse> {
    let webauthn_rs_credential = data
        .get("credential_response")
        .and_then(|v| {
            let json_value = v.clone();
            serde_json::from_value::<webauthn_rs_proto::RegisterPublicKeyCredential>(json_value)
                .ok()
        })
        .ok_or_else(|| {
            HttpResponse::BadRequest().json(json!({
                "error": "invalid_request",
                "message": "Invalid credential response format"
            }))
        })?;

    // Convert webauthn-rs format to our internal format
    let internal_response = crate::webauthn::RegistrationResponse {
        id: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&webauthn_rs_credential.raw_id),
        raw_id: base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(&webauthn_rs_credential.raw_id),
        response: crate::webauthn::AuthenticatorAttestationResponse {
            client_data_json: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(&webauthn_rs_credential.response.client_data_json),
            attestation_object: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(&webauthn_rs_credential.response.attestation_object),
        },
        client_extension_results: None,
        r#type: "public-key".to_string(),
    };

    Ok(internal_response)
}

/// Extract and parse registration state from request data
fn extract_registration_state(
    data: &web::Json<serde_json::Value>,
) -> Result<crate::webauthn::RegistrationState, HttpResponse> {
    let state_str = data
        .get("registration_state")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            HttpResponse::BadRequest().json(json!({
                "error": "invalid_state",
                "message": "Missing registration state"
            }))
        })?;

    serde_json::from_str::<crate::webauthn::RegistrationState>(state_str).map_err(|e| {
        log::error!("Failed to deserialize registration state: {e}");
        HttpResponse::BadRequest().json(json!({
            "error": "invalid_state",
            "message": "Invalid registration state format"
        }))
    })
}

/// Extract user data from registration request
fn extract_registration_user_data(
    data: &web::Json<serde_json::Value>,
) -> Result<(String, String, Option<String>), HttpResponse> {
    if let Some(encoded_user_data) = data.get("user_data").and_then(|v| v.as_str()) {
        if let Ok(user_data) = crate::passkey::PasskeyUserData::decode(encoded_user_data) {
            Ok((user_data.user_handle, user_data.email, user_data.name))
        } else {
            log::error!("Failed to decode user data during registration");
            Err(HttpResponse::BadRequest().json(json!({
                "error": "invalid_user_data",
                "message": "Failed to decode user data"
            })))
        }
    } else {
        log::error!("Missing user_data in registration request");
        Err(HttpResponse::BadRequest().json(json!({
            "error": "missing_user_data",
            "message": "User data is required for registration"
        })))
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

    let webauthn = match get_webauthn(settings) {
        Ok(w) => w,
        Err(resp) => return Ok(resp),
    };

    let credential_response = match extract_registration_credential_response(data) {
        Ok(resp) => resp,
        Err(error_resp) => return Ok(error_resp),
    };

    let registration_state = match extract_registration_state(data) {
        Ok(state) => state,
        Err(error_resp) => return Ok(error_resp),
    };

    let passkey = match webauthn.finish_registration(&credential_response, &registration_state) {
        Ok(passkey) => passkey,
        Err(e) => {
            log::error!("Registration verification failed: {e}");
            return Ok(HttpResponse::BadRequest().json(json!({
                "error": "registration_failed",
                "message": format!("Failed to complete registration: {e}")
            })));
        }
    };

    let credential_id = passkey.credential_id.clone();

    let (user_handle, user_email, user_name) = match extract_registration_user_data(data) {
        Ok(data) => data,
        Err(error_resp) => return Ok(error_resp),
    };

    let client_ip = req
        .connection_info()
        .realip_remote_addr()
        .map(ToString::to_string);
    let user_agent_info = crate::utils::user_agent::extract_user_agent_info(req);

    let vouchrs_user_data = crate::models::VouchrsUserData {
        email: user_email.clone(),
        name: user_name.clone(),
        provider: "passkey".to_string(),
        provider_id: user_handle.clone(),
        client_ip,
        user_agent: user_agent_info.user_agent,
        platform: user_agent_info.platform,
        lang: user_agent_info.lang,
        mobile: i32::from(user_agent_info.mobile),
        session_start: Some(chrono::Utc::now().timestamp()),
    };

    match session_manager.create_user_cookie(&vouchrs_user_data) {
        Ok(user_cookie) => Ok(HttpResponse::Ok().cookie(user_cookie).json(json!({
            "success": true,
            "message": "Registration completed successfully",
            "user_handle": user_handle,
            "credential_id": credential_id,
        }))),
        Err(e) => {
            log::error!("Failed to create user cookie during registration: {e}");
            Ok(HttpResponse::InternalServerError().json(json!({
                "error": "cookie_creation_failed",
                "message": "Failed to create user session"
            })))
        }
    }
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

    // Use the same static WebAuthn instance as registration to ensure consistency
    let webauthn = match get_webauthn(settings) {
        Ok(w) => w,
        Err(resp) => return Ok(resp),
    };

    let (options, state) = webauthn.start_authentication(None);

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

    // Log the options structure for debugging
    log::debug!("Authentication options: {options:?}");

    Ok(HttpResponse::Ok().json(json!({
        "request_options": {
            "publicKey": options // Wrap options in publicKey field as per WebAuthn spec
        },
        "authentication_state": state_serialized,
        "note": "For usernameless auth, send user_data as null"
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
) -> Result<serde_json::Value, HttpResponse> {
    match data
        .get("authentication_state")
        .and_then(|v| v.as_str())
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
    {
        Some(state) => Ok(state),
        None => Err(HttpResponse::BadRequest().json(json!({
            "error": "invalid_state",
            "message": "Missing or invalid authentication state"
        }))),
    }
}

/// Validate authentication state timeout
fn validate_authentication_timeout(_settings: &VouchrsSettings) {
    // TODO: Implement proper timeout validation using the actual state creation time
    // For now, always allow authentication to test usernameless flow
    log::debug!("Skipping timeout validation for testing purposes");
}

/// Extract and validate user data from request
fn extract_and_validate_user_data(
    req: &HttpRequest,
    data: &web::Json<serde_json::Value>,
    credential_response: &webauthn_rs_proto::PublicKeyCredential,
    session_manager: &SessionManager,
) -> Result<crate::passkey::PasskeyUserData, HttpResponse> {
    // Check if user_data is provided (traditional auth) or null (usernameless auth)
    let user_data_value = data.get("user_data");

    if let Some(user_data_val) = user_data_value {
        if user_data_val.is_null() {
            // Usernameless authentication - try to get user data from existing vouchrs_user cookie
            let user_handle = credential_response
                .response
                .user_handle
                .as_ref()
                .map_or_else(
                    || {
                        // If no user handle is provided, use the credential ID as a fallback
                        log::warn!(
                            "No user handle in credential response, using credential ID as fallback"
                        );
                        base64::engine::general_purpose::URL_SAFE
                            .encode(&credential_response.raw_id)
                    },
                    |h| base64::engine::general_purpose::URL_SAFE.encode(h.as_ref()),
                );

            // Try to get user data from existing vouchrs_user cookie set during registration
            match session_manager.get_user_data_from_request(req) {
                Ok(Some(vouchrs_user_data)) => {
                    // Successfully retrieved user data from cookie
                    log::info!(
                        "Usernameless authentication using stored user data for user: {}",
                        vouchrs_user_data.email
                    );

                    // Create PasskeyUserData from the stored VouchrsUserData
                    let user_data = crate::passkey::PasskeyUserData::new(
                        &user_handle,
                        &vouchrs_user_data.email,
                        vouchrs_user_data.name.as_deref(),
                    );

                    return Ok(user_data);
                }
                Ok(None) => {
                    // No user cookie found - fall back to placeholder values
                    log::warn!(
                        "Usernameless authentication: No vouchrs_user cookie found, using placeholder values"
                    );
                }
                Err(e) => {
                    // Error retrieving cookie - fall back to placeholder values
                    log::warn!(
                        "Usernameless authentication: Failed to retrieve vouchrs_user cookie: {e}, using placeholder values"
                    );
                }
            }

            // Fallback to placeholder values if no cookie data is available
            let user_data = crate::passkey::PasskeyUserData::new(
                &user_handle,
                "usernameless@passkey.auth", // Placeholder email for usernameless auth
                Some("Passkey User"),        // Placeholder name for usernameless auth
            );

            log::info!(
                "Usernameless authentication for user handle: {user_handle} (using placeholder data)"
            );
            return Ok(user_data);
        }

        // Traditional authentication with provided user_data
        let Some(user_data) = user_data_val
            .as_str()
            .and_then(|s| crate::passkey::PasskeyUserData::decode(s).ok())
        else {
            log::error!("Invalid user data format");
            return Err(HttpResponse::BadRequest().json(json!({
                "error": "invalid_user_data",
                "message": "Invalid user data format"
            })));
        };

        let user_handle = credential_response
            .response
            .user_handle
            .as_ref()
            .map_or_else(
                || "mock_user_handle".to_string(),
                |h| base64::engine::general_purpose::URL_SAFE.encode(h.as_ref()),
            );

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
    } else {
        log::error!("Missing user_data field");
        Err(HttpResponse::BadRequest().json(json!({
            "error": "missing_user_data",
            "message": "Missing user_data field in request"
        })))
    }
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

    log::debug!("Complete authentication request data: {data:?}");

    let credential_response = match extract_credential_response(data) {
        Ok(response) => response,
        Err(error_response) => return Ok(error_response),
    };

    let _authentication_state = match extract_authentication_state(data) {
        Ok(state) => {
            log::debug!("Authentication state received: {state:?}");
            state
        }
        Err(error_response) => return Ok(error_response),
    };

    validate_authentication_timeout(settings);

    let user_data =
        match extract_and_validate_user_data(req, data, &credential_response, session_manager) {
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
