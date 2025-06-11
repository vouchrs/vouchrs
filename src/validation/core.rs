//! Validation utilities for extracting and validating data from JSON requests
//!
//! This module provides reusable validation patterns to reduce code duplication
//! across handlers that need to extract and validate fields from JSON requests.

use actix_web::HttpResponse;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::utils::responses::ResponseBuilder;

// ===============================
// COMMON FIELD EXTRACTION PATTERNS
// ===============================

/// Extract a required field from JSON data with automatic type conversion and error handling
///
/// This function consolidates the common pattern of:
/// 1. Getting a field from JSON data
/// 2. Converting it to the target type using serde
/// 3. Returning appropriate error responses if either step fails
///
/// # Arguments
///
/// * `data` - The JSON data to extract from
/// * `field_name` - The name of the field to extract
///
/// # Returns
///
/// * `Ok(T)` - The successfully parsed field value
/// * `Err(HttpResponse)` - An appropriate error response (missing or invalid field)
///
/// # Errors
///
/// Returns an error if the field is missing or if the field cannot be parsed into type T.
///
/// # Example
///
/// ```rust,no_run
/// use serde_json::json;
/// use vouchrs::validation::extract_required_field;
/// use serde_json::Value;
///
/// let data = json!({
///     "registration_state": {
///         "challenge": "abc123"
///     }
/// });
///
/// let state: Value = extract_required_field(&data, "registration_state").unwrap();
/// ```
pub fn extract_required_field<T: DeserializeOwned>(
    data: &Value,
    field_name: &str,
) -> Result<T, HttpResponse> {
    let field = data
        .get(field_name)
        .ok_or_else(|| ResponseBuilder::missing_field(field_name))?;

    serde_json::from_value(field.clone()).map_err(|e| {
        log::error!("Failed to parse {field_name}: {e}");
        ResponseBuilder::invalid_field(field_name, "Invalid format")
    })
}

/// Extract a required string field from JSON data
///
/// This is a specialized version of `extract_required_field` that specifically
/// handles string fields.
///
/// # Arguments
///
/// * `data` - The JSON data to extract from
/// * `field_name` - The name of the string field to extract
///
/// # Returns
///
/// * `Ok(String)` - The string value
/// * `Err(HttpResponse)` - An appropriate error response
///
/// # Errors
///
/// Returns an error if the field is missing or is not a string.
///
/// # Example
///
/// ```rust,no_run
/// use serde_json::json;
/// use vouchrs::validation::extract_required_string;
///
/// let data = json!({
///     "user_data": "encoded_user_data_here"
/// });
///
/// let user_data_str = extract_required_string(&data, "user_data").unwrap();
/// ```
pub fn extract_required_string(data: &Value, field_name: &str) -> Result<String, HttpResponse> {
    data.get(field_name)
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
        .ok_or_else(|| ResponseBuilder::missing_field(field_name))
}

/// Extract an optional field from JSON data with type conversion
///
/// Similar to `extract_required_field` but for optional fields.
/// Returns `None` if the field is missing or null, `Some(T)` if present and valid,
/// or an error response if present but invalid.
///
/// # Arguments
///
/// * `data` - The JSON data to extract from
/// * `field_name` - The name of the field to extract
///
/// # Returns
///
/// * `Ok(Some(T))` - The successfully parsed field value
/// * `Ok(None)` - The field was missing or null
/// * `Err(HttpResponse)` - The field was present but invalid
///
/// # Errors
///
/// Returns an error if the field is present but cannot be parsed into type T.
pub fn extract_optional_field<T: DeserializeOwned>(
    data: &Value,
    field_name: &str,
) -> Result<Option<T>, HttpResponse> {
    match data.get(field_name) {
        Some(field) if !field.is_null() => {
            serde_json::from_value(field.clone())
                .map(Some)
                .map_err(|e| {
                    log::error!("Failed to parse optional {field_name}: {e}");
                    ResponseBuilder::invalid_field(field_name, "Invalid format")
                })
        }
        _ => Ok(None),
    }
}

// ===============================
// SPECIALIZED VALIDATION PATTERNS
// ===============================

/// Validate and extract credential response from JSON data
///
/// This consolidates the common pattern used in passkey handlers for extracting
/// credential responses with consistent error handling.
///
/// # Type Parameters
///
/// * `T` - The credential type (`RegisterPublicKeyCredential` or `PublicKeyCredential`)
///
/// # Errors
///
/// Returns an error if the credential response is missing or invalid.
///
/// # Example
///
/// ```rust,no_run
/// use serde_json::{json, Value};
/// use vouchrs::validation::extract_credential_response;
///
/// let data = json!({"credential_response": {"type": "public-key"}});
/// let credential: Value = extract_credential_response(&data).unwrap();
/// ```
pub fn extract_credential_response<T: DeserializeOwned>(data: &Value) -> Result<T, HttpResponse> {
    let credential = data
        .get("credential_response")
        .ok_or_else(ResponseBuilder::missing_credential)?;

    serde_json::from_value(credential.clone()).map_err(|e| {
        log::error!("Failed to parse credential: {e}");
        ResponseBuilder::invalid_credential("Invalid credential format")
    })
}

/// Validate and extract authentication/registration state from JSON data
///
/// This consolidates the pattern for extracting `WebAuthn` state objects with
/// consistent error handling and logging.
///
/// # Arguments
///
/// * `data` - The JSON data to extract from
/// * `state_field_name` - The field name (`"registration_state"` or `"authentication_state"`)
///
/// # Type Parameters
///
/// * `T` - The state type (`PasskeyRegistration` or `PasskeyAuthentication`)
///
/// # Errors
///
/// Returns an error if the state is missing or invalid.
///
/// # Example
///
/// ```rust,no_run
/// use serde_json::{json, Value};
/// use vouchrs::validation::extract_state;
///
/// let data = json!({"registration_state": {"challenge": "abc123"}});
/// let state: Value = extract_state(&data, "registration_state").unwrap();
/// ```
pub fn extract_state<T: DeserializeOwned>(
    data: &Value,
    state_field_name: &str,
) -> Result<T, HttpResponse> {
    let state = data
        .get(state_field_name)
        .ok_or_else(ResponseBuilder::missing_state)?;

    serde_json::from_value(state.clone()).map_err(|e| {
        log::error!("Failed to parse {state_field_name}: {e}");
        ResponseBuilder::invalid_state("Invalid state format")
    })
}

/// Extract and decode user data from JSON with specialized error handling
///
/// This function handles the specific pattern of extracting base64-encoded
/// user data and decoding it with appropriate error messages.
///
/// # Arguments
///
/// * `data` - The JSON data to extract from
/// * `decoder_fn` - A function that decodes the string data
///
/// # Errors
///
/// Returns an error if the user data is missing, invalid, or cannot be decoded.
///
/// # Example
///
/// ```rust,no_run
/// use serde_json::json;
/// use vouchrs::validation::extract_and_decode_user_data;
///
/// let data = json!({"user_data": "base64data"});
/// let decode_fn = |s: &str| -> Result<String, &'static str> { Ok(s.to_string()) };
/// let user_data = extract_and_decode_user_data(&data, decode_fn).unwrap();
/// ```
pub fn extract_and_decode_user_data<T, F, E>(data: &Value, decoder_fn: F) -> Result<T, HttpResponse>
where
    F: FnOnce(&str) -> Result<T, E>,
    E: std::fmt::Display,
{
    let encoded_user_data = extract_required_string(data, "user_data")?;

    decoder_fn(&encoded_user_data).map_err(|e| {
        log::error!("Failed to decode user data: {e}");
        ResponseBuilder::invalid_user_data("Failed to decode user data")
    })
}

// ===============================
// VALIDATION COMBINATORS
// ===============================

/// Validate multiple required fields at once with early return on first error
///
/// This is useful when you need to extract several fields and want to fail fast
/// on the first validation error rather than collecting all errors.
///
/// # Example
///
/// ```rust,no_run
/// use serde_json::{json, Value};
/// use vouchrs::{validate_all_required, validation::extract_required_field};
///
/// let data = json!({
///     "credential_response": {"type": "public-key"},
///     "registration_state": {"challenge": "abc123"}
/// });
///
/// let (credential, state) = validate_all_required!(
///     &data,
///     credential: Value = "credential_response",
///     state: Value = "registration_state"
/// ).unwrap();
/// ```
#[macro_export]
macro_rules! validate_all_required {
    ($data:expr, $($name:ident: $type:ty = $field:expr),+ $(,)?) => {
        (|| -> Result<_, actix_web::HttpResponse> {
            $(
                let $name: $type = $crate::validation::core::extract_required_field($data, $field)?;
            )+
            Ok(($($name,)+))
        })()
    };
}

// ===============================
// JWT AND TOKEN VALIDATION HELPERS
// ===============================

/// Extract claims from a JWT-like structure with base64 decoding
///
/// This consolidates the pattern used in JWT validation for decoding and parsing
/// base64-encoded JWT parts.
///
/// # Arguments
///
/// * `encoded_data` - Base64-encoded string to decode
/// * `data_type` - Description of the data type for error messages ("header", "claims", etc.)
///
/// # Errors
///
/// Returns an error if the data cannot be base64 decoded or parsed as JSON.
///
/// # Example
///
/// ```rust,no_run
/// use serde_json::{json, Value};
/// use base64::Engine;
/// use vouchrs::validation::decode_and_parse_jwt_part;
///
/// let header = json!({"alg": "RS256", "typ": "JWT"});
/// let header_str = serde_json::to_string(&header).unwrap();
/// let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header_str.as_bytes());
/// let result: Value = decode_and_parse_jwt_part(&encoded, "header").unwrap();
/// ```
pub fn decode_and_parse_jwt_part<T: DeserializeOwned>(
    encoded_data: &str,
    data_type: &str,
) -> Result<T, String> {
    use base64::Engine as _;

    let decoded_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded_data)
        .map_err(|e| format!("Invalid {data_type} encoding: {e}"))?;

    serde_json::from_slice(&decoded_bytes).map_err(|e| format!("Invalid {data_type} JSON: {e}"))
}

/// Extract string or array audiences from JWT claims
///
/// This consolidates the pattern for handling JWT audience claims which can be
/// either a single string or an array of strings.
///
/// # Arguments
///
/// * `aud_claim` - The audience claim value from JWT
///
/// # Returns
///
/// A vector of audience strings (empty if no valid audiences found)
#[must_use]
pub fn extract_audiences_from_claim(aud_claim: &Value) -> Vec<String> {
    match aud_claim {
        Value::String(aud) => vec![aud.clone()],
        Value::Array(auds) => auds
            .iter()
            .filter_map(|v| v.as_str().map(ToString::to_string))
            .collect(),
        _ => vec![],
    }
}

/// Extract name information from various claim formats
///
/// This consolidates the pattern for extracting user names from different OAuth providers
/// that use different claim structures (Google's `"name"` vs others' `"given_name"`/`"family_name"`).
///
/// # Arguments
///
/// * `claims` - The JWT claims object
///
/// # Returns
///
/// The extracted name string, or None if no name information is available
#[must_use]
pub fn extract_name_from_claims(claims: &Value) -> Option<String> {
    // Try direct 'name' field first (Google format)
    if let Some(name) = claims.get("name").and_then(|v| v.as_str()) {
        if !name.trim().is_empty() {
            log::debug!("Extracted name from 'name' claim: {name}");
            return Some(name.to_string());
        }
    }

    // Try given_name + family_name (Apple and others)
    let given_name = claims
        .get("given_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let family_name = claims
        .get("family_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if !given_name.is_empty() || !family_name.is_empty() {
        let full_name = format!("{given_name} {family_name}").trim().to_string();
        if !full_name.is_empty() {
            log::debug!("Extracted name from given_name + family_name: {full_name}");
            return Some(full_name);
        }
    }

    log::debug!("No name information found in claims");
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use serde::{Deserialize, Serialize};
    use serde_json::json;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestStruct {
        field1: String,
        field2: i32,
    }

    #[derive(Debug, Deserialize)]
    struct TestHeader {
        #[allow(dead_code)]
        alg: String,
        typ: String,
    }

    #[test]
    fn test_extract_required_field_success() {
        let data = json!({
            "test_field": {
                "field1": "test_value",
                "field2": 42
            }
        });

        let result: Result<TestStruct, _> = extract_required_field(&data, "test_field");
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.field1, "test_value");
        assert_eq!(parsed.field2, 42);
    }

    #[test]
    fn test_extract_required_field_missing() {
        let data = json!({
            "other_field": "value"
        });

        let result: Result<TestStruct, _> = extract_required_field(&data, "test_field");
        assert!(result.is_err());
        // Note: In a real test, you'd check the error response details
    }

    #[test]
    fn test_extract_required_field_invalid() {
        let data = json!({
            "test_field": "not_an_object"
        });

        let result: Result<TestStruct, _> = extract_required_field(&data, "test_field");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_required_string_success() {
        let data = json!({
            "user_data": "encoded_string_here"
        });

        let result = extract_required_string(&data, "user_data");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "encoded_string_here");
    }

    #[test]
    fn test_extract_required_string_missing() {
        let data = json!({
            "other_field": "value"
        });

        let result = extract_required_string(&data, "user_data");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_optional_field_present() {
        let data = json!({
            "optional_field": {
                "field1": "test",
                "field2": 123
            }
        });

        let result: Result<Option<TestStruct>, _> = extract_optional_field(&data, "optional_field");
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_extract_optional_field_missing() {
        let data = json!({
            "other_field": "value"
        });

        let result: Result<Option<TestStruct>, _> = extract_optional_field(&data, "optional_field");
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_extract_optional_field_null() {
        let data = json!({
            "optional_field": null
        });

        let result: Result<Option<TestStruct>, _> = extract_optional_field(&data, "optional_field");
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_extract_audiences_from_claim_string() {
        let aud_claim = json!("single-audience");
        let audiences = extract_audiences_from_claim(&aud_claim);
        assert_eq!(audiences, vec!["single-audience"]);
    }

    #[test]
    fn test_extract_audiences_from_claim_array() {
        let aud_claim = json!(["audience1", "audience2", 123]);
        let audiences = extract_audiences_from_claim(&aud_claim);
        assert_eq!(audiences, vec!["audience1", "audience2"]);
    }

    #[test]
    fn test_extract_audiences_from_claim_invalid() {
        let aud_claim = json!(123);
        let audiences = extract_audiences_from_claim(&aud_claim);
        assert!(audiences.is_empty());
    }

    #[test]
    fn test_extract_name_from_claims_direct() {
        let claims = json!({
            "name": "John Doe"
        });

        let name = extract_name_from_claims(&claims);
        assert_eq!(name, Some("John Doe".to_string()));
    }

    #[test]
    fn test_extract_name_from_claims_parts() {
        let claims = json!({
            "given_name": "John",
            "family_name": "Doe"
        });

        let name = extract_name_from_claims(&claims);
        assert_eq!(name, Some("John Doe".to_string()));
    }

    #[test]
    fn test_extract_name_from_claims_missing() {
        let claims = json!({
            "sub": "12345",
            "email": "test@example.com"
        });

        let name = extract_name_from_claims(&claims);
        assert_eq!(name, None);
    }

    #[test]
    fn test_decode_and_parse_jwt_part_success() {
        let header = json!({
            "alg": "RS256",
            "typ": "JWT"
        });
        let header_str = serde_json::to_string(&header).unwrap();
        let encoded =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header_str.as_bytes());

        let result: Result<TestHeader, _> = decode_and_parse_jwt_part(&encoded, "header");
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.typ, "JWT");
    }

    #[test]
    fn test_decode_and_parse_jwt_part_invalid_base64() {
        let result: Result<TestHeader, _> = decode_and_parse_jwt_part("invalid-base64", "header");
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.contains("Invalid header encoding"));
    }

    #[test]
    fn test_validate_all_required_macro() {
        let data = json!({
            "field1": {
                "field1": "value1",
                "field2": 1
            },
            "field2": {
                "field1": "value2",
                "field2": 2
            }
        });

        // Test the macro directly with match to avoid type inference
        let result = validate_all_required!(
            &data,
            first: TestStruct = "field1",
            second: TestStruct = "field2"
        );

        assert!(result.is_ok());
        let (first, second) = result.unwrap();
        assert_eq!(first.field1, "value1");
        assert_eq!(second.field1, "value2");
    }
}
