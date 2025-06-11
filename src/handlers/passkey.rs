//! Passkey request handlers
//!
//! This module provides HTTP handlers for passkey authentication operations,
//! delegating to the `PasskeyAuthenticationService` for cleaner separation of concerns.

use actix_web::{web, HttpRequest, HttpResponse, Result};
use serde::Deserialize;
use serde_json::json;

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
    // Validate the registration request using the new validator
    if let Err(error_response) =
        crate::validation::RegistrationRequestValidator::validate_registration_request(
            &data.name,
            &data.email,
        )
    {
        return Ok(error_response);
    }

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
    // Use the new structured validator
    let validated_data =
        match crate::validation::PasskeyValidator::validate_registration_data(&data) {
            Ok(data) => data,
            Err(error_response) => return Ok(error_response),
        };

    let registration_data = PasskeyRegistrationData {
        credential_response: validated_data.credential_response,
        registration_state: validated_data.registration_state,
        user_data: validated_data.user_data,
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
    // Use the new structured validator
    let validated_data = match crate::validation::PasskeyValidator::validate_authentication_data(
        &data,
        &req,
        &session_manager,
    ) {
        Ok(data) => data,
        Err(error_response) => return Ok(error_response),
    };

    let authentication_data = PasskeyAuthenticationData {
        credential_response: validated_data.credential_response,
        authentication_state: validated_data.authentication_state,
        user_data: validated_data.user_data,
    };

    // Delegate to SessionManager for unified session handling
    match session_manager.handle_passkey_authentication_json(&req, authentication_data) {
        Ok(response) => Ok(response),
        Err(error_response) => Ok(error_response),
    }
}
