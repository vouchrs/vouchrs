use serde_json::json;
use vouchrs::validation::{PasskeyValidator, RegistrationRequestValidator};

#[tokio::test]
async fn test_passkey_validator_directly() {
    // Test the validator directly with invalid data
    let invalid_data = json!({
        "rawId": "invalid_base64!@#",
        "response": {
            "attestationObject": "",
            "clientDataJSON": ""
        }
    });

    let result = PasskeyValidator::validate_registration_data(&invalid_data);
    assert!(result.is_err());

    // Test with missing fields
    let missing_fields = json!({
        "rawId": "dGVzdA=="
        // Missing response field
    });

    let result = PasskeyValidator::validate_registration_data(&missing_fields);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_registration_request_validator() {
    // Test with invalid registration request
    let result = RegistrationRequestValidator::validate_registration_request("", "Test User");
    assert!(result.is_err());

    // Test with valid request
    let result =
        RegistrationRequestValidator::validate_registration_request("testuser", "test@example.com");
    assert!(result.is_ok());

    // Test with invalid email
    let result =
        RegistrationRequestValidator::validate_registration_request("testuser", "invalid-email");
    assert!(result.is_err());
}

#[tokio::test]
async fn test_validators_handle_edge_cases() {
    // Test with null values
    let null_data = json!({
        "rawId": null,
        "response": {
            "attestationObject": "test",
            "clientDataJSON": "test"
        }
    });

    let result = PasskeyValidator::validate_registration_data(&null_data);
    assert!(result.is_err());

    // Test with wrong data types
    let wrong_type_data = json!({
        "rawId": 12345, // Should be string
        "response": {
            "attestationObject": "test",
            "clientDataJSON": "test"
        }
    });

    let result = PasskeyValidator::validate_registration_data(&wrong_type_data);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_registration_request_edge_cases() {
    // Test with very long name
    let long_name = "a".repeat(101);
    let result =
        RegistrationRequestValidator::validate_registration_request(&long_name, "test@example.com");
    assert!(result.is_err());

    // Test with name containing invalid characters
    let result = RegistrationRequestValidator::validate_registration_request(
        "test<script>",
        "test@example.com",
    );
    assert!(result.is_err());

    // Test with very long email
    let long_email = format!("{}@example.com", "a".repeat(250));
    let result = RegistrationRequestValidator::validate_registration_request("test", &long_email);
    assert!(result.is_err());

    // Test with multiple @ symbols
    let result =
        RegistrationRequestValidator::validate_registration_request("test", "test@@example.com");
    assert!(result.is_err());
}
