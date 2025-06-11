//! Passkey validation utilities
//!
//! This module consolidates passkey validation patterns into reusable, focused
//! validation functions to reduce duplication and improve maintainability.

use actix_web::{HttpRequest, HttpResponse};
use base64::Engine;
use serde_json::Value;
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration};
use webauthn_rs_proto::{PublicKeyCredential, RegisterPublicKeyCredential};

use crate::passkey::PasskeyUserData;
use crate::session::SessionManager;
use crate::utils::responses::ResponseBuilder;
use crate::validation::core::{
    extract_and_decode_user_data, extract_credential_response, extract_state,
};

/// Passkey validation utilities with structured validation steps
pub struct PasskeyValidator;

/// Validated passkey registration data
#[derive(Debug)]
pub struct ValidatedRegistrationData {
    pub credential_response: RegisterPublicKeyCredential,
    pub registration_state: PasskeyRegistration,
    pub user_data: PasskeyUserData,
}

/// Validated passkey authentication data
#[derive(Debug)]
pub struct ValidatedAuthenticationData {
    pub credential_response: PublicKeyCredential,
    pub authentication_state: PasskeyAuthentication,
    pub user_data: Option<PasskeyUserData>,
}

impl PasskeyValidator {
    /// Validate and extract passkey registration data
    ///
    /// This consolidates the validation pattern used in `complete_registration`
    /// into a focused, testable function.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Credential response is missing or invalid
    /// - Registration state is missing or invalid
    /// - User data is missing or cannot be decoded
    pub fn validate_registration_data(
        data: &Value,
    ) -> Result<ValidatedRegistrationData, HttpResponse> {
        // Extract credential response
        let credential_response: RegisterPublicKeyCredential = extract_credential_response(data)?;

        // Extract registration state
        let registration_state: PasskeyRegistration = extract_state(data, "registration_state")?;

        // Extract and decode user data
        let user_data: PasskeyUserData =
            extract_and_decode_user_data(data, PasskeyUserData::decode)?;

        Ok(ValidatedRegistrationData {
            credential_response,
            registration_state,
            user_data,
        })
    }

    /// Validate and extract passkey authentication data
    ///
    /// This consolidates the validation pattern used in `complete_authentication`
    /// with support for both traditional and usernameless authentication flows.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Credential response is missing or invalid
    /// - Authentication state is missing or invalid
    /// - User data extraction fails
    pub fn validate_authentication_data(
        data: &Value,
        req: &HttpRequest,
        session_manager: &SessionManager,
    ) -> Result<ValidatedAuthenticationData, HttpResponse> {
        // Extract credential response
        let credential_response: PublicKeyCredential = extract_credential_response(data)?;

        // Extract authentication state
        let authentication_state: PasskeyAuthentication =
            extract_state(data, "authentication_state")?;

        // Extract user data (optional for usernameless auth)
        let user_data = Self::extract_user_data_for_authentication(
            data,
            &credential_response,
            req,
            session_manager,
        )?;

        Ok(ValidatedAuthenticationData {
            credential_response,
            authentication_state,
            user_data,
        })
    }

    /// Extract user data for authentication with support for usernameless flows
    ///
    /// This consolidates the complex logic for handling different authentication
    /// scenarios into a focused function with clear error handling.
    fn extract_user_data_for_authentication(
        data: &Value,
        credential_response: &PublicKeyCredential,
        req: &HttpRequest,
        session_manager: &SessionManager,
    ) -> Result<Option<PasskeyUserData>, HttpResponse> {
        let user_data_value = data.get("user_data");

        match user_data_value {
            Some(user_data_val) if user_data_val.is_null() => {
                // Usernameless authentication - try to get from cookie or create minimal data
                Self::handle_usernameless_authentication(credential_response, req, session_manager)
            }
            Some(user_data_val) => {
                // Traditional authentication with provided user_data
                Self::handle_traditional_authentication(user_data_val)
            }
            None => {
                // No user_data field provided - treat as usernameless
                Self::handle_usernameless_authentication(credential_response, req, session_manager)
            }
        }
    }

    /// Handle usernameless authentication flow
    ///
    /// Attempts to retrieve user data from stored session cookies or creates
    /// minimal user data from the credential response.
    fn handle_usernameless_authentication(
        credential_response: &PublicKeyCredential,
        req: &HttpRequest,
        session_manager: &SessionManager,
    ) -> Result<Option<PasskeyUserData>, HttpResponse> {
        match session_manager.get_user_data_from_request(req) {
            Ok(Some(stored_user_data)) => {
                let user_handle = Self::extract_user_handle(credential_response);

                Ok(Some(PasskeyUserData::new(
                    &user_handle,
                    Some(&stored_user_data.email),
                    stored_user_data.name.as_deref(),
                )))
            }
            Ok(None) => {
                // No stored user data available for usernameless auth
                Ok(None)
            }
            Err(e) => {
                log::error!("Failed to retrieve user data from request: {e}");
                Err(ResponseBuilder::authentication_failed(
                    "Failed to retrieve user session",
                ))
            }
        }
    }

    /// Handle traditional authentication with provided user data
    ///
    /// Extracts and decodes user data from the request payload.
    fn handle_traditional_authentication(
        user_data_val: &Value,
    ) -> Result<Option<PasskeyUserData>, HttpResponse> {
        match user_data_val.as_str() {
            Some(encoded_data) if !encoded_data.trim().is_empty() => {
                match PasskeyUserData::decode(encoded_data) {
                    Ok(user_data) => Ok(Some(user_data)),
                    Err(e) => {
                        log::error!("Failed to decode user data: {e}");
                        Err(ResponseBuilder::bad_request()
                            .with_error_code("invalid_user_data")
                            .with_message("Failed to decode user data")
                            .build())
                    }
                }
            }
            Some(_) => {
                // Empty string provided
                Err(ResponseBuilder::bad_request()
                    .with_error_code("invalid_user_data")
                    .with_message("User data cannot be empty")
                    .build())
            }
            None => {
                // Not a string value
                Err(ResponseBuilder::bad_request()
                    .with_error_code("invalid_user_data")
                    .with_message("User data must be a string")
                    .build())
            }
        }
    }

    /// Extract user handle from credential response
    ///
    /// Handles both cases where `user_handle` is provided in the response
    /// or needs to be derived from the `raw_id`.
    fn extract_user_handle(credential_response: &PublicKeyCredential) -> String {
        credential_response
            .response
            .user_handle
            .as_ref()
            .map_or_else(
                || base64::engine::general_purpose::URL_SAFE.encode(&credential_response.raw_id),
                |h| base64::engine::general_purpose::URL_SAFE.encode(h.as_ref()),
            )
    }
}

/// Registration request validation
pub struct RegistrationRequestValidator;

impl RegistrationRequestValidator {
    /// Validate registration request data
    ///
    /// Ensures that name and email are provided and meet basic requirements.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Name is empty, too long, or contains invalid characters
    /// - Email is empty, too long, or has invalid format
    pub fn validate_registration_request(name: &str, email: &str) -> Result<(), HttpResponse> {
        Self::validate_name(name)?;
        Self::validate_email(email)?;
        Ok(())
    }

    /// Validate the name field
    fn validate_name(name: &str) -> Result<(), HttpResponse> {
        let trimmed_name = name.trim();

        if trimmed_name.is_empty() {
            return Err(ResponseBuilder::bad_request()
                .with_error_code("invalid_name")
                .with_message("Name cannot be empty")
                .build());
        }

        if trimmed_name.len() > 100 {
            return Err(ResponseBuilder::bad_request()
                .with_error_code("invalid_name")
                .with_message("Name cannot exceed 100 characters")
                .build());
        }

        // Check for potentially dangerous characters
        if trimmed_name
            .chars()
            .any(|c| c.is_control() || matches!(c, '<' | '>' | '"' | '\'' | '&'))
        {
            return Err(ResponseBuilder::bad_request()
                .with_error_code("invalid_name")
                .with_message("Name contains invalid characters")
                .build());
        }

        Ok(())
    }

    /// Validate the email field
    fn validate_email(email: &str) -> Result<(), HttpResponse> {
        let trimmed_email = email.trim();

        if trimmed_email.is_empty() {
            return Err(ResponseBuilder::bad_request()
                .with_error_code("invalid_email")
                .with_message("Email cannot be empty")
                .build());
        }

        if trimmed_email.len() > 254 {
            return Err(ResponseBuilder::bad_request()
                .with_error_code("invalid_email")
                .with_message("Email cannot exceed 254 characters")
                .build());
        }

        // Basic email validation (more comprehensive validation could be added)
        if !trimmed_email.contains('@') || !trimmed_email.contains('.') {
            return Err(ResponseBuilder::bad_request()
                .with_error_code("invalid_email")
                .with_message("Invalid email format")
                .build());
        }

        // Check for multiple @ symbols
        if trimmed_email.matches('@').count() != 1 {
            return Err(ResponseBuilder::bad_request()
                .with_error_code("invalid_email")
                .with_message("Invalid email format")
                .build());
        }

        // Split on @ and validate both parts exist and are non-empty
        let parts: Vec<&str> = trimmed_email.split('@').collect();
        if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
            return Err(ResponseBuilder::bad_request()
                .with_error_code("invalid_email")
                .with_message("Invalid email format")
                .build());
        }

        // Domain part must contain at least one dot and have content after it
        let domain = parts[1];
        if !domain.contains('.') || domain.ends_with('.') || domain.starts_with('.') {
            return Err(ResponseBuilder::bad_request()
                .with_error_code("invalid_email")
                .with_message("Invalid email format")
                .build());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_registration_request_validation() {
        // Test valid registration data
        assert!(RegistrationRequestValidator::validate_registration_request(
            "John Doe",
            "john@example.com"
        )
        .is_ok());

        // Test invalid name
        assert!(RegistrationRequestValidator::validate_registration_request(
            "",
            "john@example.com"
        )
        .is_err());

        assert!(RegistrationRequestValidator::validate_registration_request(
            "John<script>",
            "john@example.com"
        )
        .is_err());

        // Test invalid email
        assert!(
            RegistrationRequestValidator::validate_registration_request("John Doe", "").is_err()
        );

        assert!(RegistrationRequestValidator::validate_registration_request(
            "John Doe",
            "not-an-email"
        )
        .is_err());

        assert!(RegistrationRequestValidator::validate_registration_request(
            "John Doe",
            "john@@example.com"
        )
        .is_err());
    }

    #[test]
    fn test_name_validation() {
        // Valid names
        assert!(RegistrationRequestValidator::validate_name("John Doe").is_ok());
        assert!(RegistrationRequestValidator::validate_name("José María").is_ok());
        assert!(RegistrationRequestValidator::validate_name("李小明").is_ok());

        // Invalid names
        assert!(RegistrationRequestValidator::validate_name("").is_err());
        assert!(RegistrationRequestValidator::validate_name("   ").is_err());
        assert!(RegistrationRequestValidator::validate_name("John<script>").is_err());
        assert!(RegistrationRequestValidator::validate_name("John\"quote").is_err());
        assert!(RegistrationRequestValidator::validate_name(&"a".repeat(101)).is_err());
    }

    #[test]
    fn test_email_validation() {
        // Valid emails
        assert!(RegistrationRequestValidator::validate_email("user@example.com").is_ok());
        assert!(
            RegistrationRequestValidator::validate_email("test.email+tag@domain.co.uk").is_ok()
        );

        // Invalid emails
        assert!(RegistrationRequestValidator::validate_email("").is_err());
        assert!(RegistrationRequestValidator::validate_email("   ").is_err());
        assert!(RegistrationRequestValidator::validate_email("notanemail").is_err());
        assert!(RegistrationRequestValidator::validate_email("user@").is_err());
        assert!(RegistrationRequestValidator::validate_email("@domain.com").is_err());
        assert!(RegistrationRequestValidator::validate_email("user@@domain.com").is_err());
        assert!(RegistrationRequestValidator::validate_email(&format!(
            "{}@example.com",
            "a".repeat(250)
        ))
        .is_err());
    }
    #[test]
    fn test_user_handle_extraction() {
        // This test demonstrates the concept but requires actual webauthn_rs_proto types
        // In a real implementation, we would need to construct valid PublicKeyCredential instances
        // For now, we'll test the logic indirectly through the validation functions

        // Test that the extraction method exists and can be called
        // (the actual testing would require valid webauthn credential structures)
        // TODO: Add comprehensive credential testing when mock credentials are available
    }

    #[test]
    fn test_traditional_authentication_handling() {
        // Test with valid encoded user data
        let _encoded_data = json!("valid_encoded_string");
        // Note: This test would need a mock PasskeyUserData::decode function
        // or we'd need to create valid encoded data

        // Test with empty string
        let empty_data = json!("");
        let result = PasskeyValidator::handle_traditional_authentication(&empty_data);
        assert!(result.is_err());

        // Test with non-string data
        let invalid_data = json!(123);
        let result = PasskeyValidator::handle_traditional_authentication(&invalid_data);
        assert!(result.is_err());

        // Test with null data
        let null_data = json!(null);
        let result = PasskeyValidator::handle_traditional_authentication(&null_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_validation_method_separation() {
        // Each validation method should be testable independently

        // Test name validation separately
        assert!(RegistrationRequestValidator::validate_name("Valid Name").is_ok());
        assert!(RegistrationRequestValidator::validate_name("").is_err());

        // Test email validation separately
        assert!(RegistrationRequestValidator::validate_email("valid@email.com").is_ok());
        assert!(RegistrationRequestValidator::validate_email("invalid").is_err());

        // Test combined validation
        assert!(RegistrationRequestValidator::validate_registration_request(
            "Valid Name",
            "valid@email.com"
        )
        .is_ok());

        // Should fail on first invalid field (name)
        assert!(
            RegistrationRequestValidator::validate_registration_request("", "valid@email.com")
                .is_err()
        );

        // Should fail on second invalid field (email)
        assert!(RegistrationRequestValidator::validate_registration_request(
            "Valid Name",
            "invalid"
        )
        .is_err());
    }
}
