// Apple-specific utility functions
use crate::oauth::OAuthCallback;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Parse and process Apple user information from various sources
///
/// This function can:
/// 1. Parse a raw JSON Value into `AppleUserInfo` (when called with just the value)
/// 2. Process OAuth callback data and existing user info (when called with callback and existing info)
///
/// Apple Sign In can provide user information in two ways:
/// - In the initial token response (handled by the OAuth provider)
/// - In the callback data's 'user' parameter (handled here)
///
/// When both sources are provided, the callback data is prioritized

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AppleUserName {
    #[serde(rename = "firstName")]
    pub first_name: Option<String>,
    #[serde(rename = "lastName")]
    pub last_name: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AppleUserInfo {
    pub name: AppleUserName,
    pub email: Option<String>,
}

/// Process Apple user information from a JSON value
/// 
/// # Arguments
/// 
/// * `source` - The JSON value containing Apple user information
/// * `fallback_info` - Optional fallback information to use if parsing fails
/// 
/// # Returns
/// 
/// Returns `Some(AppleUserInfo)` if parsing succeeds or fallback is available, `None` otherwise
#[must_use]
pub fn process_apple_user_info(
    user_value: &Value,
    existing_user_info: Option<AppleUserInfo>,
) -> Option<AppleUserInfo> {
    // If we already have user info, return it
    if existing_user_info.is_some() {
        return existing_user_info;
    }

    // Try to parse from JSON value
    if let Ok(user_info) = serde_json::from_value::<AppleUserInfo>(user_value.clone()) {
        return Some(user_info);
    }

    // If it's a JSON string, try to parse the string
    if let Value::String(json_str) = user_value {
        if let Ok(user_info) = serde_json::from_str::<AppleUserInfo>(json_str) {
            return Some(user_info);
        }
    }

    None
}

/// Process Apple user info from OAuth callback data
///
/// This is a convenience wrapper around `process_apple_user_info` that handles
/// extracting the user JSON from the callback data
#[must_use]
pub fn process_apple_callback(
    callback_data: &OAuthCallback,
    fallback_info: Option<AppleUserInfo>,
) -> Option<AppleUserInfo> {
    callback_data
        .user
        .as_ref()
        .and_then(|user_json| process_apple_user_info(user_json, None))
        .or(fallback_info)
}

/// Generate Apple client secret JWT
/// This function creates a properly signed JWT that can be used as a client secret
/// with Apple's OAuth endpoints.
/// 
/// # Errors
/// 
/// Returns an error if:
/// - Team ID is not configured
/// - Key ID is not configured
/// - Private key path is not configured
/// - Private key file cannot be read
/// - Private key cannot be parsed
/// - JWT serialization fails
pub fn generate_jwt_client_secret(
    jwt_config: &crate::settings::JwtSigningConfig,
    client_id: &str,
) -> Result<String, String> {
    use crate::utils::crypto::{create_jwt, create_jwt_header, JwtAlgorithm};
    use chrono::{Duration, Utc};

    // Get required values using the getter methods
    let team_id = jwt_config
        .get_team_id()
        .ok_or_else(|| "Team ID not configured for Apple provider".to_string())?;
    let key_id = jwt_config
        .get_key_id()
        .ok_or_else(|| "Key ID not configured for Apple provider".to_string())?;
    let private_key_path = jwt_config
        .get_private_key_path()
        .ok_or_else(|| "Private key path not configured for Apple provider".to_string())?;

    // Read the private key file
    let private_key_pem = std::fs::read_to_string(&private_key_path)
        .map_err(|_| "Failed to read Apple private key file".to_string())?;

    // Create JWT header with Apple-specific key ID
    let header = create_jwt_header(&JwtAlgorithm::ES256, Some(&key_id));

    // Create JWT payload with Apple-specific claims
    let now = Utc::now();
    let exp = now + Duration::minutes(5);

    let payload = serde_json::json!({
        "iss": team_id,
        "iat": now.timestamp(),
        "exp": exp.timestamp(),
        "aud": "https://appleid.apple.com",
        "sub": client_id
    });

    // Use the generic JWT creation function
    let jwt = create_jwt(&header, &payload, JwtAlgorithm::ES256, private_key_pem.as_bytes())
        .map_err(|e| format!("Failed to create Apple JWT: {e}"))?;

    log::debug!("Generated Apple client secret JWT");
    Ok(jwt)
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_apple_user_info_from_object() {
        let apple_user_info = AppleUserInfo {
            name: AppleUserName {
                first_name: Some("John".to_string()),
                last_name: Some("Doe".to_string()),
            },
            email: Some("john.doe@apple.com".to_string()),
        };

        let value = serde_json::to_value(&apple_user_info).unwrap();
        let parsed = process_apple_user_info(&value, None).unwrap();

        assert_eq!(parsed.email, Some("john.doe@apple.com".to_string()));
        assert_eq!(parsed.name.first_name, Some("John".to_string()));
        assert_eq!(parsed.name.last_name, Some("Doe".to_string()));
    }

    #[test]
    fn test_process_apple_user_info_from_string() {
        let apple_user_info = AppleUserInfo {
            name: AppleUserName {
                first_name: Some("Jane".to_string()),
                last_name: Some("Smith".to_string()),
            },
            email: Some("jane.smith@apple.com".to_string()),
        };

        let json_string = serde_json::to_string(&apple_user_info).unwrap();
        let value = Value::String(json_string);
        let parsed = process_apple_user_info(&value, None).unwrap();

        assert_eq!(parsed.email, Some("jane.smith@apple.com".to_string()));
        assert_eq!(parsed.name.first_name, Some("Jane".to_string()));
        assert_eq!(parsed.name.last_name, Some("Smith".to_string()));
    }

    #[test]
    fn test_process_apple_user_info_with_fallback() {
        // Test with invalid value but valid fallback
        let fallback = AppleUserInfo {
            name: AppleUserName {
                first_name: Some("Fallback".to_string()),
                last_name: Some("User".to_string()),
            },
            email: Some("fallback@example.com".to_string()),
        };

        let value = Value::Number(serde_json::Number::from(42));
        let result = process_apple_user_info(&value, Some(fallback.clone()));

        assert!(result.is_some());
        let user = result.unwrap();
        assert_eq!(user.email, Some("fallback@example.com".to_string()));
    }
}
