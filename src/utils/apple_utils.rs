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
