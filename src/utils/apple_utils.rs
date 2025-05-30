// Apple-specific utility functions
use crate::models::AppleUserInfo;
use crate::jwt_handlers::types::OAuthCallback;
use log::debug;
use serde_json::Value;

/// Parse and process Apple user information from various sources
///
/// This function can:
/// 1. Parse a raw JSON Value into AppleUserInfo (when called with just the value)
/// 2. Process OAuth callback data and existing user info (when called with callback and existing info)
///
/// Apple Sign In can provide user information in two ways:
/// - In the initial token response (handled by the OAuth provider)
/// - In the callback data's 'user' parameter (handled here)
///
/// When both sources are provided, the callback data is prioritized
pub fn process_apple_user_info(
    source: &Value, 
    fallback_info: Option<AppleUserInfo>
) -> Option<AppleUserInfo> {
    // Try to parse the Apple user info from the JSON value
    let parse_result = match source {
        Value::Object(_) => serde_json::from_value::<AppleUserInfo>(source.clone()),
        Value::String(s) => serde_json::from_str::<AppleUserInfo>(s),
        _ => Err(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::Other, 
            "user field is not an object or JSON string"
        )))
    };
    
    // Return the parsed value or fall back to existing info
    match parse_result {
        Ok(parsed_user) => {
            debug!("Parsed Apple user info: {:?}", parsed_user);
            Some(parsed_user)
        },
        Err(_) => {
            debug!("Failed to parse Apple user info, using fallback if available");
            fallback_info
        }
    }
}

/// Process Apple user info from OAuth callback data
///
/// This is a convenience wrapper around process_apple_user_info that handles
/// extracting the user JSON from the callback data
pub fn process_apple_callback(
    callback_data: &OAuthCallback,
    fallback_info: Option<AppleUserInfo>
) -> Option<AppleUserInfo> {
    callback_data.user.as_ref()
        .and_then(|user_json| process_apple_user_info(user_json, None))
        .or(fallback_info)
}

/// Generate Apple client secret JWT
/// This function creates a properly signed JWT that can be used as a client secret
/// with Apple's OAuth endpoints.
pub fn generate_apple_client_secret(jwt_config: &crate::settings::JwtSigningConfig, client_id: &str) -> Result<String, String> {
    use p256::ecdsa::{SigningKey, Signature, signature::Signer};
    use p256::pkcs8::DecodePrivateKey;
    use base64::{Engine as _, engine::general_purpose};
    use chrono::{Utc, Duration};
    
    // Get required values using the getter methods
    let team_id = jwt_config.get_team_id()
        .ok_or_else(|| "Team ID not configured for Apple provider".to_string())?;
    let key_id = jwt_config.get_key_id()
        .ok_or_else(|| "Key ID not configured for Apple provider".to_string())?;
    let private_key_path = jwt_config.get_private_key_path()
        .ok_or_else(|| "Private key path not configured for Apple provider".to_string())?;

    // Read the private key file
    let private_key_pem = std::fs::read_to_string(&private_key_path)
        .map_err(|_| "Failed to read Apple private key file".to_string())?;

    // Use the correct p256 method for parsing PKCS#8 PEM
    let signing_key = SigningKey::from_pkcs8_pem(&private_key_pem)
        .map_err(|e| format!("Failed to parse Apple private key: {:?}", e))?;

    // Create JWT header
    let header = serde_json::json!({
        "alg": "ES256",
        "kid": key_id,
        "typ": "JWT"
    });

    // Create JWT claims
    let now = Utc::now();
    let exp = now + Duration::minutes(5);
    
    let claims = serde_json::json!({
        "iss": team_id,
        "iat": now.timestamp(),
        "exp": exp.timestamp(),
        "aud": "https://appleid.apple.com",
        "sub": client_id
    });

    // Encode header and payload
    let header_json = serde_json::to_string(&header)
        .map_err(|_| "Failed to serialize JWT header".to_string())?;
    let claims_json = serde_json::to_string(&claims)
        .map_err(|_| "Failed to serialize JWT claims".to_string())?;

    let header_b64 = general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    let payload_b64 = general_purpose::URL_SAFE_NO_PAD.encode(claims_json.as_bytes());

    let message = format!("{}.{}", header_b64, payload_b64);

    // Sign with ES256
    let signature: Signature = signing_key.sign(message.as_bytes());
    let signature_b64 = general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes());

    let jwt = format!("{}.{}", message, signature_b64);
    
    log::debug!("Generated Apple client secret JWT");
    Ok(jwt)
}

/// Generate Apple client secret JWT for token refresh
/// This function creates a properly signed JWT that can be used as a client secret
/// with Apple's OAuth token refresh endpoint.
pub fn generate_apple_client_secret_for_refresh(jwt_config: &crate::settings::JwtSigningConfig, provider_settings: &crate::settings::ProviderSettings) -> Result<String, String> {
    use serde::{Serialize, Deserialize};
    
    #[derive(Debug, Serialize, Deserialize)]
    struct AppleJwtClaims {
        iss: String,    // Team ID
        iat: i64,       // Issued at time
        exp: i64,       // Expiration time
        aud: String,    // Audience (always "https://appleid.apple.com")
        sub: String,    // Client ID
    }

    // Get client_id from provider settings
    let client_id = provider_settings.get_client_id()
        .ok_or_else(|| "Client ID not configured for Apple provider".to_string())?;
    
    // Delegate to the general purpose function
    let jwt = generate_apple_client_secret(jwt_config, &client_id)?;
    
    log::debug!("Generated Apple client secret JWT for token refresh");
    Ok(jwt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AppleUserInfo, AppleUserName};

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
