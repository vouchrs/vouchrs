// Session builder for creating VouchrSession from ID token claims
//
// This module provides a unified approach for extracting user information from OAuth ID tokens
// and mapping them to VouchrSession fields. It replaces the complex provider-specific extraction
// logic with a standardized approach that works with all OAuth providers that issue standard
// OpenID Connect ID tokens.
//
// Standard ID Token Claims Mapping:
// - sub (subject) -> provider_id: Unique identifier for the user from the provider
// - email -> user_email: User's email address
// - iat (issued at) -> created_at: When the token was issued
// - exp (expires) -> expires_at: When the token expires
// - iss (issuer) -> provider: OAuth provider (normalized from issuer URL)
// - name, given_name+family_name -> user_name: User's display name (optional)

use crate::models::{CompleteSessionData, AppleUserInfo};
use crate::handlers::helpers::decode_jwt_payload;
use chrono::{DateTime, Utc, TimeZone};
use log::{debug, warn, info};
use serde_json::Value;

pub struct SessionBuilder;

impl SessionBuilder {
    /// Creates a CompleteSessionData from OAuth tokens, extracting standard claims from the ID token
    /// and using Apple user info to fill in missing fields if available
    pub fn build_session(
        provider: String,
        id_token: Option<String>,
        refresh_token: Option<String>,
        expires_at: DateTime<Utc>,
    ) -> Result<CompleteSessionData, String> {
        Self::build_session_with_apple_info(provider, id_token, refresh_token, expires_at, None)
    }

    /// Creates a CompleteSessionData from OAuth tokens with optional Apple user info for fallback
    pub fn build_session_with_apple_info(
        provider: String,
        id_token: Option<String>,
        refresh_token: Option<String>,
        expires_at: DateTime<Utc>,
        apple_user_info: Option<AppleUserInfo>,
    ) -> Result<CompleteSessionData, String> {
        let id_token_ref = id_token.as_ref()
            .ok_or("No ID token available")?;

        let claims = decode_jwt_payload(id_token_ref)
            .map_err(|e| format!("Failed to decode ID token: {}", e))?;

        info!("Building session from ID token claims for provider: {}", provider);
        debug!("ID token claims: {}", serde_json::to_string_pretty(&claims).unwrap_or_default());

        // Extract required claims
        let provider_id = Self::extract_subject(&claims)?;
        let user_email = Self::extract_email(&claims).or_else(|| {
            // Fallback to Apple user info if email not in token
            if let Some(ref apple_info) = apple_user_info {
                if let Some(ref email) = apple_info.email {
                    debug!("Using Apple user info email as fallback: {}", email);
                    return Some(email.clone());
                }
            }
            debug!("No email found in ID token or Apple user info, using default");
            Some("user@example.com".to_string())
        }).unwrap(); // This unwrap is safe because we provide a default
        
        // Extract optional claims
        let mut user_name = Self::extract_name(&claims);
        
        // Use Apple user info name as fallback if name not found in ID token
        if user_name.is_none() {
            if let Some(ref apple_info) = apple_user_info {
                let apple_name = apple_info.name.full_name();
                if !apple_name.trim().is_empty() {
                    debug!("Using Apple user info name as fallback: {}", apple_name);
                    user_name = Some(apple_name);
                }
            }
        }
        let created_at = Self::extract_issued_at(&claims);
        // let expires_at = Self::extract_expires_at(&claims);

        // Normalize provider name from issuer if available
        let normalized_provider = Self::normalize_provider(&provider, &claims);

        info!("Session built successfully - Email: {}, Provider: {}, Provider ID: {}, Name: {:?}", 
              user_email, normalized_provider, provider_id, user_name);

        Ok(CompleteSessionData {
            user_email,
            user_name,
            provider: normalized_provider,
            provider_id,
            id_token: id_token.clone(),
            refresh_token,
            expires_at,
            created_at: created_at.unwrap_or_else(Utc::now),
        })
    }

    /// Extract the subject (sub) claim - maps to provider_id
    fn extract_subject(claims: &Value) -> Result<String, String> {
        claims.get("sub")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or("Missing or invalid 'sub' claim in ID token".to_string())
    }

    /// Extract the email claim - maps to user_email (returns Option for fallback logic)
    pub fn extract_email(claims: &Value) -> Option<String> {
        claims.get("email")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Extract the name claim - maps to user_name (optional)
    fn extract_name(claims: &Value) -> Option<String> {
        // Try different name claim formats used by different providers
        
        // Google uses 'name' field directly
        if let Some(name) = claims.get("name").and_then(|v| v.as_str()) {
            if !name.trim().is_empty() {
                debug!("Extracted name from 'name' claim: {}", name);
                return Some(name.to_string());
            }
        }

        // Apple and others might use given_name + family_name
        let given_name = claims.get("given_name").and_then(|v| v.as_str()).unwrap_or("");
        let family_name = claims.get("family_name").and_then(|v| v.as_str()).unwrap_or("");
        
        if !given_name.is_empty() || !family_name.is_empty() {
            let full_name = format!("{} {}", given_name, family_name).trim().to_string();
            if !full_name.is_empty() {
                debug!("Extracted name from given_name + family_name: {}", full_name);
                return Some(full_name);
            }
        }

        debug!("No name information found in ID token claims");
        None
    }

    /// Generic timestamp extraction helper
    fn extract_timestamp(claims: &Value, field_name: &str) -> Option<DateTime<Utc>> {
        claims.get(field_name)
            .and_then(|v| v.as_i64())
            .and_then(|timestamp| {
                match Utc.timestamp_opt(timestamp, 0) {
                    chrono::LocalResult::Single(dt) => {
                        debug!("Extracted {} from '{}' claim: {}", field_name, field_name, dt);
                        Some(dt)
                    }
                    _ => {
                        warn!("Invalid '{}' timestamp in ID token: {}", field_name, timestamp);
                        None
                    }
                }
            })
    }

    /// Extract the issued at (iat) claim - maps to created_at
    fn extract_issued_at(claims: &Value) -> Option<DateTime<Utc>> {
        Self::extract_timestamp(claims, "iat")
    }

    /// Normalize provider name from issuer claim if available
    fn normalize_provider(provider: &str, claims: &Value) -> String {
        if let Some(issuer) = claims.get("iss").and_then(|v| v.as_str()) {
            debug!("Found issuer claim: {}", issuer);
            
            // Map common issuer values to normalized provider names
            if issuer.contains("accounts.google.com") {
                return "google".to_string();
            } else if issuer.contains("appleid.apple.com") {
                return "apple".to_string();
            }
        }
        
        // Fall back to the provider passed in from the state
        provider.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AppleUserInfo, AppleUserName};
    use chrono::Utc;
    use base64::Engine as _;
    use serde_json::json;

    fn minimal_id_token(sub: &str) -> String {
        // JWT with only 'sub' claim, base64-encoded header and payload, signature ignored
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\"}");
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("{{\"sub\":\"{}\"}}", sub).as_bytes());
        format!("{}.{}.ignored", header, payload)
    }

    #[test]
    fn test_apple_userinfo_copied_to_vouchrsession() {
        let id_token = Some(minimal_id_token("apple-sub-123"));
        let refresh_token = Some("refresh123".to_string());
        let expires_at = Utc::now() + chrono::Duration::hours(1);
        let apple_user_info = AppleUserInfo {
            name: AppleUserName {
                first_name: Some("Jane".to_string()),
                last_name: Some("Doe".to_string()),
            },
            email: Some("jane.doe@apple.com".to_string()),
        };
        // Test with AppleUserInfo as struct (Value::Object case)
        let session = SessionBuilder::build_session_with_apple_info(
            "apple".to_string(),
            id_token.clone(),
            refresh_token.clone(),
            expires_at,
            Some(apple_user_info.clone()),
        ).expect("Session should be built");
        assert_eq!(session.user_email, apple_user_info.email.clone().unwrap());
        assert_eq!(session.user_name.clone().unwrap(), apple_user_info.name.full_name());
        assert_eq!(session.provider, "apple");
        assert_eq!(session.provider_id, "apple-sub-123");

        // Test that session building works correctly with Apple user info
        // The important part is that the Apple user info is properly incorporated into the session
        assert_eq!(session.user_email, "jane.doe@apple.com");
        assert_eq!(session.user_name.unwrap(), "Jane Doe");
    }

    #[test]
    fn test_extract_subject_success() {
        let claims = json!({
            "sub": "12345",
            "email": "test@example.com"
        });
        
        assert_eq!(SessionBuilder::extract_subject(&claims).unwrap(), "12345");
    }

    #[test]
    fn test_extract_subject_missing() {
        let claims = json!({
            "email": "test@example.com"
        });
        
        assert!(SessionBuilder::extract_subject(&claims).is_err());
    }

    #[test]
    fn test_extract_name_google_format() {
        let claims = json!({
            "name": "John Doe"
        });
        
        assert_eq!(SessionBuilder::extract_name(&claims), Some("John Doe".to_string()));
    }

    #[test]
    fn test_extract_name_apple_format() {
        let claims = json!({
            "given_name": "John",
            "family_name": "Doe"
        });
        
        assert_eq!(SessionBuilder::extract_name(&claims), Some("John Doe".to_string()));
    }

    #[test]
    fn test_extract_name_missing() {
        let claims = json!({
            "sub": "12345",
            "email": "test@example.com"
        });
        
        assert_eq!(SessionBuilder::extract_name(&claims), None);
    }
}
