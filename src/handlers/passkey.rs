//! Passkey request handlers
//!
//! This module provides HTTP handlers for passkey authentication operations,
//! delegating to the `PasskeyAuthenticationService` for cleaner separation of concerns.

use actix_web::{web, HttpRequest, HttpResponse, Result};
use serde::{Deserialize, Serialize};
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

/// Passkey state data for secure cookie storage
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PasskeyStateData {
    /// The serialized passkey state (registration or authentication)
    state_data: String,
    /// Client IP address bound to this state
    client_ip: Option<String>,
    /// Creation timestamp
    created_at: chrono::DateTime<chrono::Utc>,
    /// Operation type (registration or authentication)
    operation_type: String,
}

/// Cookie names for passkey state
const PASSKEY_REGISTRATION_STATE_COOKIE: &str = "vouchrs_passkey_reg_state";
const PASSKEY_AUTHENTICATION_STATE_COOKIE: &str = "vouchrs_passkey_auth_state";

/// Create encrypted cookie for passkey state storage
fn create_passkey_state_cookie(
    state_data: &str,
    client_ip: Option<&str>,
    operation_type: &str,
    cookie_name: &str,
    session_manager: &SessionManager,
    timeout_seconds: u64,
) -> Result<actix_web::cookie::Cookie<'static>, PasskeyError> {
    use crate::session::cookie::CookieOptions;

    let passkey_state = PasskeyStateData {
        state_data: state_data.to_string(),
        client_ip: client_ip.map(std::string::ToString::to_string),
        created_at: chrono::Utc::now(),
        operation_type: operation_type.to_string(),
    };

    let options = CookieOptions {
        http_only: true,
        secure: true,
        same_site: actix_web::cookie::SameSite::Lax,
        path: "/".to_string(),
        max_age: actix_web::cookie::time::Duration::seconds(
            i64::try_from(timeout_seconds).unwrap_or(300), // Default to 5 minutes if conversion fails
        ),
    };

    session_manager
        .cookie_factory()
        .create_cookie(cookie_name, Some(&passkey_state), options)
        .map_err(|e| {
            PasskeyError::ServiceUnavailable(format!("Failed to create state cookie: {e}"))
        })
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
    req: HttpRequest,
    data: web::Json<RegistrationRequest>,
    settings: web::Data<VouchrsSettings>,
    session_manager: web::Data<SessionManager>,
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

            // Serialize the registration state for cookie storage
            let state_json = match serde_json::to_string(&result.state) {
                Ok(json) => json,
                Err(e) => {
                    log::error!("Failed to serialize registration state: {e}");
                    return Ok(ResponseBuilder::internal_server_error()
                        .with_error_code("serialization_failed")
                        .with_message("Failed to prepare registration state")
                        .build());
                }
            };

            // Extract client IP for binding
            let (client_ip, _) = crate::session::utils::extract_client_info(&req);

            // Create encrypted cookie for state storage
            let state_cookie = match create_passkey_state_cookie(
                &state_json,
                client_ip.as_deref(),
                "registration",
                PASSKEY_REGISTRATION_STATE_COOKIE,
                &session_manager,
                settings.passkeys.timeout_seconds,
            ) {
                Ok(cookie) => cookie,
                Err(e) => {
                    log::error!("Failed to create registration state cookie: {e}");
                    return Ok(error_to_response(e));
                }
            };

            // Return creation options without the raw state
            Ok(HttpResponse::Ok().cookie(state_cookie).json(json!({
                "creation_options": result.options,
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
///
/// # Panics
///
/// This function will panic if the incoming JSON data is not an object.
/// This should not happen in normal operation as the data comes from the client's
/// `WebAuthn` credential response which is always a JSON object.
pub async fn complete_registration(
    req: HttpRequest,
    data: web::Json<serde_json::Value>,
    session_manager: web::Data<SessionManager>,
) -> Result<HttpResponse> {
    // Extract registration state from encrypted cookie
    let state_json = match extract_passkey_state_from_cookie(
        &req,
        PASSKEY_REGISTRATION_STATE_COOKIE,
        "registration",
        &session_manager,
    ) {
        Ok(state) => state,
        Err(e) => {
            log::error!("Failed to extract registration state from cookie: {e}");
            return Ok(error_to_response(e));
        }
    };

    // Deserialize the registration state
    let registration_state: webauthn_rs::prelude::PasskeyRegistration =
        match serde_json::from_str(&state_json) {
            Ok(state) => state,
            Err(e) => {
                log::error!("Failed to deserialize registration state: {e}");
                return Ok(ResponseBuilder::bad_request()
                    .with_error_code("invalid_state")
                    .with_message("Invalid registration state")
                    .build());
            }
        };

    // Create a modified data object that includes the state from the cookie
    let mut data_with_state = data.as_object().unwrap().clone();
    data_with_state.insert(
        "registration_state".to_string(),
        serde_json::to_value(registration_state).unwrap(),
    );
    let data_with_state = serde_json::Value::Object(data_with_state);

    // Use the new structured validator with the reconstructed data
    let validated_data =
        match crate::validation::PasskeyValidator::validate_registration_data(&data_with_state) {
            Ok(data) => data,
            Err(error_response) => return Ok(error_response),
        };

    let registration_data = PasskeyRegistrationData {
        credential_response: validated_data.credential_response,
        registration_state: validated_data.registration_state,
        user_data: validated_data.user_data,
    };

    // Delegate to SessionManager for unified session handling
    let mut response = match session_manager.handle_passkey_registration(
        &req,
        registration_data,
        crate::session::manager::ResponseType::Json,
    ) {
        Ok(response) => response,
        Err(error_response) => error_response,
    };

    // Clear the registration state cookie on completion (success or failure)
    let clear_cookie = actix_web::cookie::Cookie::build(PASSKEY_REGISTRATION_STATE_COOKIE, "")
        .http_only(true)
        .secure(true)
        .same_site(actix_web::cookie::SameSite::Lax)
        .path("/")
        .max_age(actix_web::cookie::time::Duration::seconds(0))
        .finish();

    // Add the clear cookie to the response
    response
        .add_cookie(&clear_cookie)
        .map_err(|_| {
            log::error!("Failed to add clear cookie to response");
        })
        .ok();

    Ok(response)
}

/// Start passkey authentication using service
///
/// # Errors
///
/// Returns an error if:
/// - The service is not available (passkeys disabled)
/// - `WebAuthn` authentication initialization fails
pub async fn start_authentication(
    req: HttpRequest,
    _data: web::Json<serde_json::Value>,
    settings: web::Data<VouchrsSettings>,
    session_manager: web::Data<SessionManager>,
) -> Result<HttpResponse> {
    let service = PasskeyAuthenticationServiceImpl::new(settings.as_ref().clone());

    match service.start_authentication() {
        Ok(result) => {
            // Serialize the authentication state for cookie storage
            let state_json = match serde_json::to_string(&result.state) {
                Ok(json) => json,
                Err(e) => {
                    log::error!("Failed to serialize authentication state: {e}");
                    return Ok(ResponseBuilder::internal_server_error()
                        .with_error_code("serialization_failed")
                        .with_message("Failed to prepare authentication state")
                        .build());
                }
            };

            // Extract client IP for binding
            let (client_ip, _) = crate::session::utils::extract_client_info(&req);

            // Create encrypted cookie for state storage
            let state_cookie = match create_passkey_state_cookie(
                &state_json,
                client_ip.as_deref(),
                "authentication",
                PASSKEY_AUTHENTICATION_STATE_COOKIE,
                &session_manager,
                settings.passkeys.timeout_seconds,
            ) {
                Ok(cookie) => cookie,
                Err(e) => {
                    log::error!("Failed to create authentication state cookie: {e}");
                    return Ok(error_to_response(e));
                }
            };

            // Return request options without the raw state
            Ok(HttpResponse::Ok().cookie(state_cookie).json(json!({
                "request_options": result.options,
                "user_data": null
            })))
        }
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
///
/// # Panics
///
/// This function will panic if the incoming JSON data is not an object.
/// This should not happen in normal operation as the data comes from the client's
/// `WebAuthn` credential response which is always a JSON object.
pub async fn complete_authentication(
    req: HttpRequest,
    data: web::Json<serde_json::Value>,
    session_manager: web::Data<SessionManager>,
) -> Result<HttpResponse> {
    // Extract authentication state from encrypted cookie
    let state_json = match extract_passkey_state_from_cookie(
        &req,
        PASSKEY_AUTHENTICATION_STATE_COOKIE,
        "authentication",
        &session_manager,
    ) {
        Ok(state) => state,
        Err(e) => {
            log::error!("Failed to extract authentication state from cookie: {e}");
            return Ok(error_to_response(e));
        }
    };

    // Deserialize the authentication state
    let authentication_state: webauthn_rs::prelude::PasskeyAuthentication =
        match serde_json::from_str(&state_json) {
            Ok(state) => state,
            Err(e) => {
                log::error!("Failed to deserialize authentication state: {e}");
                return Ok(ResponseBuilder::bad_request()
                    .with_error_code("invalid_state")
                    .with_message("Invalid authentication state")
                    .build());
            }
        };

    // Create a modified data object that includes the state from the cookie
    let mut data_with_state = data.as_object().unwrap().clone();
    data_with_state.insert(
        "authentication_state".to_string(),
        serde_json::to_value(authentication_state).unwrap(),
    );
    let data_with_state = serde_json::Value::Object(data_with_state);

    // Use the new structured validator with the reconstructed data
    let validated_data = match crate::validation::PasskeyValidator::validate_authentication_data(
        &data_with_state,
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
    let mut response = match session_manager.handle_passkey_authentication(
        &req,
        authentication_data,
        crate::session::manager::ResponseType::Json,
    ) {
        Ok(response) => response,
        Err(error_response) => error_response,
    };

    // Clear the authentication state cookie on completion (success or failure)
    let clear_cookie = actix_web::cookie::Cookie::build(PASSKEY_AUTHENTICATION_STATE_COOKIE, "")
        .http_only(true)
        .secure(true)
        .same_site(actix_web::cookie::SameSite::Lax)
        .path("/")
        .max_age(actix_web::cookie::time::Duration::seconds(0))
        .finish();

    // Add the clear cookie to the response
    response
        .add_cookie(&clear_cookie)
        .map_err(|_| {
            log::error!("Failed to add clear cookie to response");
        })
        .ok();

    Ok(response)
}

/// Extract and validate passkey state from cookie
fn extract_passkey_state_from_cookie(
    req: &HttpRequest,
    cookie_name: &str,
    expected_operation_type: &str,
    session_manager: &SessionManager,
) -> Result<String, PasskeyError> {
    use crate::utils::crypto::decrypt_data;

    // Get the cookie value
    let cookie_value = req
        .cookie(cookie_name)
        .ok_or_else(|| PasskeyError::InvalidRequest("Passkey state cookie not found".to_string()))?
        .value()
        .to_string();

    // Decrypt the state data
    let passkey_state: PasskeyStateData =
        decrypt_data(&cookie_value, session_manager.encryption_key()).map_err(|e| {
            PasskeyError::InvalidRequest(format!("Failed to decrypt state cookie: {e}"))
        })?;

    // Validate operation type
    if passkey_state.operation_type != expected_operation_type {
        return Err(PasskeyError::InvalidRequest(format!(
            "Invalid operation type: expected {}, got {}",
            expected_operation_type, passkey_state.operation_type
        )));
    }

    // Validate timestamp (check if expired)
    let now = chrono::Utc::now();
    let age = now.signed_duration_since(passkey_state.created_at);
    if age.num_seconds() > 300 {
        // 5 minutes maximum age for extra security
        return Err(PasskeyError::InvalidRequest(
            "Passkey state has expired".to_string(),
        ));
    }

    // Validate client IP binding
    let (current_client_ip, _) = crate::session::utils::extract_client_info(req);
    if passkey_state.client_ip != current_client_ip {
        log::warn!(
            "Client IP mismatch in passkey operation: stored={:?}, current={:?}",
            passkey_state.client_ip,
            current_client_ip
        );
        return Err(PasskeyError::InvalidRequest(
            "Client context validation failed".to_string(),
        ));
    }

    Ok(passkey_state.state_data)
}
