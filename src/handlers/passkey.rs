//! Passkey request handlers
//!
//! This module provides HTTP handlers for passkey authentication operations,
//! delegating to the `PasskeyAuthenticationService` for cleaner separation of concerns.

use actix_web::{web, HttpRequest, HttpResponse, Result};
use base64::Engine;
use serde::Deserialize;
use serde_json::json;
use webauthn_rs::prelude::*;
use webauthn_rs_proto;

use crate::passkey::{
    PasskeyAuthenticationData, PasskeyAuthenticationService, PasskeyAuthenticationServiceImpl,
    PasskeyError, PasskeyRegistrationData, PasskeyRegistrationRequest, PasskeyUserData,
};
use crate::session::SessionManager;
use crate::settings::VouchrsSettings;
use crate::utils::responses::ResponseBuilder;

/// Registration request (HTTP endpoint format)
#[derive(Deserialize)]
pub struct RegistrationRequest {
    pub name: String,
    pub email: String,
}

/// Convert `PasskeyError` to HTTP response
fn error_to_response(error: PasskeyError) -> HttpResponse {
    match error {
        PasskeyError::ServiceUnavailable(_msg) => {
            ResponseBuilder::service_unavailable_with_details("Passkey service")
        }
        PasskeyError::InvalidRequest(msg) => ResponseBuilder::bad_request()
            .with_error_code("invalid_request")
            .with_message(&msg)
            .build(),
        PasskeyError::AuthenticationFailed(msg) => ResponseBuilder::authentication_failed(&msg),
        PasskeyError::RegistrationFailed(msg) => ResponseBuilder::registration_failed(&msg),
        _ => ResponseBuilder::internal_server_error()
            .with_error_code("internal_error")
            .with_message("An internal error occurred")
            .build(),
    }
}

/// Start passkey registration using service
///
/// # Errors
///
/// Returns an error if:
/// - The service is not available (passkeys disabled)
/// - Request validation fails
/// - `WebAuthn` registration initialization fails
pub async fn start_registration(
    _req: HttpRequest,
    data: web::Json<RegistrationRequest>,
    settings: web::Data<VouchrsSettings>,
) -> Result<HttpResponse> {
    let service = PasskeyAuthenticationServiceImpl::new(settings.as_ref().clone());

    let request = PasskeyRegistrationRequest {
        name: data.name.clone(),
        email: data.email.clone(),
    };

    match service.start_registration(request) {
        Ok(result) => {
            // Create user data for the registration state
            let user_data =
                PasskeyUserData::new(&result.user_handle, Some(&data.email), Some(&data.name));

            let encoded_user_data = match user_data.encode() {
                Ok(data) => data,
                Err(e) => {
                    log::error!("Failed to encode user data: {e}");
                    return Ok(ResponseBuilder::encoding_failed("user data"));
                }
            };

            Ok(HttpResponse::Ok().json(json!({
                "creation_options": result.options,
                "registration_state": result.state,
                "user_data": encoded_user_data,
                "user_handle": result.user_handle
            })))
        }
        Err(e) => Ok(error_to_response(e)),
    }
}

/// Complete passkey registration using service
///
/// # Errors
///
/// Returns an error if:
/// - The service is not available (passkeys disabled)
/// - Registration data is invalid
/// - `WebAuthn` registration fails
/// - Session creation fails
pub async fn complete_registration(
    req: HttpRequest,
    data: web::Json<serde_json::Value>,
    session_manager: web::Data<SessionManager>,
) -> Result<HttpResponse> {
    // Extract credential response
    let credential_response = match extract_credential_response(&data) {
        Ok(response) => response,
        Err(error_response) => return Ok(error_response),
    };

    // Extract registration state
    let registration_state = match extract_registration_state(&data) {
        Ok(state) => state,
        Err(error_response) => return Ok(error_response),
    };

    // Extract user data
    let user_data = match extract_user_data_for_registration(&data) {
        Ok(data) => data,
        Err(error_response) => return Ok(error_response),
    };

    let registration_data = PasskeyRegistrationData {
        credential_response,
        registration_state,
        user_data,
    };

    // Delegate to SessionManager for unified session handling
    match session_manager.handle_passkey_registration_json(&req, registration_data) {
        Ok(response) => Ok(response),
        Err(error_response) => Ok(error_response),
    }
}

/// Start passkey authentication using service
///
/// # Errors
///
/// Returns an error if:
/// - The service is not available (passkeys disabled)
/// - `WebAuthn` authentication initialization fails
pub async fn start_authentication(
    _req: HttpRequest,
    _data: web::Json<serde_json::Value>,
    settings: web::Data<VouchrsSettings>,
) -> Result<HttpResponse> {
    let service = PasskeyAuthenticationServiceImpl::new(settings.as_ref().clone());

    match service.start_authentication() {
        Ok(result) => Ok(HttpResponse::Ok().json(json!({
            "request_options": result.options,
            "authentication_state": result.state,
            "user_data": null
        }))),
        Err(e) => Ok(error_to_response(e)),
    }
}

/// Complete passkey authentication using service
///
/// # Errors
///
/// Returns an error if:
/// - The service is not available (passkeys disabled)
/// - Authentication data is invalid
/// - `WebAuthn` authentication fails
/// - Session creation fails
pub async fn complete_authentication(
    req: HttpRequest,
    data: web::Json<serde_json::Value>,
    session_manager: web::Data<SessionManager>,
) -> Result<HttpResponse> {
    // Extract credential response
    let credential_response = match extract_authentication_credential_response(&data) {
        Ok(response) => response,
        Err(error_response) => return Ok(error_response),
    };

    // Extract authentication state
    let authentication_state = match extract_authentication_state(&data) {
        Ok(state) => state,
        Err(error_response) => return Ok(error_response),
    };

    // Extract user data (optional for usernameless auth)
    let user_data =
        extract_user_data_for_authentication(&data, &credential_response, &req, &session_manager);

    let authentication_data = PasskeyAuthenticationData {
        credential_response,
        authentication_state,
        user_data,
    };

    // Delegate to SessionManager for unified session handling
    match session_manager.handle_passkey_authentication_json(&req, authentication_data) {
        Ok(response) => Ok(response),
        Err(error_response) => Ok(error_response),
    }
}

// Helper functions to extract data from requests

fn extract_credential_response(
    data: &web::Json<serde_json::Value>,
) -> Result<webauthn_rs_proto::RegisterPublicKeyCredential, HttpResponse> {
    let credential = data
        .get("credential_response")
        .ok_or_else(ResponseBuilder::missing_credential)?;

    serde_json::from_value(credential.clone()).map_err(|e| {
        log::error!("Failed to parse credential: {e}");
        ResponseBuilder::invalid_credential("Invalid credential format")
    })
}

fn extract_authentication_credential_response(
    data: &web::Json<serde_json::Value>,
) -> Result<webauthn_rs_proto::PublicKeyCredential, HttpResponse> {
    let credential = data
        .get("credential_response")
        .ok_or_else(ResponseBuilder::missing_credential)?;

    serde_json::from_value(credential.clone()).map_err(|e| {
        log::error!("Failed to parse credential: {e}");
        ResponseBuilder::invalid_credential("Invalid credential format")
    })
}

fn extract_registration_state(
    data: &web::Json<serde_json::Value>,
) -> Result<PasskeyRegistration, HttpResponse> {
    let state = data
        .get("registration_state")
        .ok_or_else(ResponseBuilder::missing_state)?;

    serde_json::from_value(state.clone()).map_err(|e| {
        log::error!("Failed to parse registration state: {e}");
        ResponseBuilder::invalid_state("Invalid registration state")
    })
}

fn extract_authentication_state(
    data: &web::Json<serde_json::Value>,
) -> Result<PasskeyAuthentication, HttpResponse> {
    let state = data
        .get("authentication_state")
        .ok_or_else(ResponseBuilder::missing_state)?;

    serde_json::from_value(state.clone()).map_err(|e| {
        log::error!("Failed to parse authentication state: {e}");
        ResponseBuilder::invalid_state("Invalid authentication state")
    })
}

fn extract_user_data_for_registration(
    data: &web::Json<serde_json::Value>,
) -> Result<PasskeyUserData, HttpResponse> {
    let encoded_user_data = data
        .get("user_data")
        .and_then(|v| v.as_str())
        .ok_or_else(ResponseBuilder::missing_user_data)?;

    PasskeyUserData::decode(encoded_user_data).map_err(|e| {
        log::error!("Failed to decode user data: {e}");
        ResponseBuilder::invalid_user_data("Failed to decode user data")
    })
}

fn extract_user_data_for_authentication(
    data: &web::Json<serde_json::Value>,
    credential_response: &webauthn_rs_proto::PublicKeyCredential,
    req: &HttpRequest,
    session_manager: &SessionManager,
) -> Option<PasskeyUserData> {
    let user_data_value = data.get("user_data");

    if let Some(user_data_val) = user_data_value {
        if user_data_val.is_null() {
            // Usernameless authentication - try to get from cookie or create minimal data
            match session_manager.get_user_data_from_request(req) {
                Ok(Some(stored_user_data)) => {
                    let user_handle = credential_response
                        .response
                        .user_handle
                        .as_ref()
                        .map_or_else(
                            || {
                                base64::engine::general_purpose::URL_SAFE
                                    .encode(&credential_response.raw_id)
                            },
                            |h| base64::engine::general_purpose::URL_SAFE.encode(h.as_ref()),
                        );

                    return Some(PasskeyUserData::new(
                        &user_handle,
                        Some(&stored_user_data.email),
                        stored_user_data.name.as_deref(),
                    ));
                }
                _ => {
                    // Return None for usernameless auth without stored data
                    return None;
                }
            }
        }

        // Traditional authentication with provided user_data
        if let Some(encoded_data) = user_data_val.as_str() {
            if let Ok(user_data) = PasskeyUserData::decode(encoded_data) {
                return Some(user_data);
            }
        }
    }

    None
}
