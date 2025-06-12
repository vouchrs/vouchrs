//! ID token processing and validation
//!
//! This module handles ID token decoding, validation, and claim extraction
//! for OAuth authentication flows. Returns simplified result structures
//! instead of full session data.

use crate::oauth::service::OAuthError;
use crate::session::auth_results::OauthResult;
use crate::utils::apple::AppleUserInfo;
use crate::utils::crypto::decode_jwt_payload;
use chrono::{DateTime, TimeZone, Utc};
use log::{debug, info, warn};
use serde_json::Value;

/// ID token processor for extracting authentication data from OAuth ID tokens
pub struct IdTokenProcessor;

impl IdTokenProcessor {
    /// Process ID token and return simple OAuth result - NO session creation logic here
    ///
    /// This method extracts claims from ID tokens and returns a simple `OauthResult`
    /// that can be directly converted to `VouchrsSession` and `VouchrsUserData` by `SessionManager`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No ID token is provided
    /// - ID token cannot be decoded
    /// - Required claims (subject) are missing
    ///
    /// # Panics
    ///
    /// Panics if no email is found in either the ID token claims or the Apple user info,
    /// as a default email should always be available from one of these sources.
    pub fn process_id_token(
        provider: &str,
        id_token: Option<&str>,
        refresh_token: Option<String>,
        expires_at: DateTime<Utc>,
        apple_user_info: Option<&AppleUserInfo>,
    ) -> Result<OauthResult, OAuthError> {
        let id_token_ref =
            id_token.ok_or_else(|| OAuthError::IdToken("No ID token available".to_string()))?;

        let claims = decode_jwt_payload(id_token_ref)
            .map_err(|e| OAuthError::IdToken(format!("Failed to decode ID token: {e}")))?;

        info!("Processing ID token claims for provider: {provider}");
        debug!(
            "ID token claims: {}",
            serde_json::to_string_pretty(&claims).unwrap_or_default()
        );

        // Extract required claims
        let provider_id = Self::extract_subject(&claims)?;
        let user_email = Self::extract_email(&claims)
            .or_else(|| {
                // Fallback to Apple user info if email not in token
                if let Some(apple_info) = apple_user_info {
                    if let Some(ref email) = apple_info.email {
                        debug!("Using Apple user info email as fallback: {email}");
                        return Some(email.clone());
                    }
                }
                debug!("No email found in ID token or Apple user info, using default");
                Some("user@example.com".to_string())
            })
            .unwrap(); // This unwrap is safe because we provide a default

        // Extract optional claims
        let mut user_name = Self::extract_name(&claims);

        // Use Apple user info name as fallback if name not found in ID token
        if user_name.is_none() {
            if let Some(apple_info) = apple_user_info {
                let apple_name = format!(
                    "{} {}",
                    apple_info.name.first_name.as_deref().unwrap_or(""),
                    apple_info.name.last_name.as_deref().unwrap_or("")
                );
                if !apple_name.trim().is_empty() {
                    debug!("Using Apple user info name as fallback: {apple_name}");
                    user_name = Some(apple_name);
                }
            }
        }

        let created_at = Self::extract_issued_at(&claims);
        let normalized_provider = Self::normalize_provider(provider, &claims);

        info!(
            "OAuth result extracted - Email: {user_email}, Provider: {normalized_provider}, Provider ID: {provider_id}, Name: {user_name:?}"
        );

        let authenticated_at = created_at.unwrap_or_else(Utc::now);

        // Return simple OauthResult - NO session creation here
        let oauth_result = OauthResult {
            provider: normalized_provider,
            provider_id,
            email: Some(user_email),
            name: user_name,
            expires_at,
            authenticated_at,
            id_token: id_token.map(String::from),
            refresh_token,
        };

        Ok(oauth_result)
    }

    /// Extract the subject (sub) claim - maps to `provider_id`
    fn extract_subject(claims: &Value) -> Result<String, OAuthError> {
        claims
            .get("sub")
            .and_then(|v| v.as_str())
            .map(std::string::ToString::to_string)
            .ok_or_else(|| {
                OAuthError::IdToken("Missing or invalid 'sub' claim in ID token".to_string())
            })
    }

    /// Extract the email claim - maps to `user_email` (returns Option for fallback logic)
    pub fn extract_email(claims: &Value) -> Option<String> {
        claims
            .get("email")
            .and_then(|v| v.as_str())
            .map(std::string::ToString::to_string)
    }

    /// Extract the name claim - maps to `user_name` (optional)
    fn extract_name(claims: &Value) -> Option<String> {
        crate::validation::extract_name_from_claims(claims)
    }

    /// Generic timestamp extraction helper
    fn extract_timestamp(claims: &Value, field_name: &str) -> Option<DateTime<Utc>> {
        claims
            .get(field_name)
            .and_then(serde_json::Value::as_i64)
            .and_then(|timestamp| {
                if let chrono::LocalResult::Single(dt) = Utc.timestamp_opt(timestamp, 0) {
                    debug!("Extracted {field_name} from '{field_name}' claim: {dt}");
                    Some(dt)
                } else {
                    warn!("Invalid '{field_name}' timestamp in ID token: {timestamp}");
                    None
                }
            })
    }

    /// Extract the issued at (iat) claim - maps to `created_at`
    fn extract_issued_at(claims: &Value) -> Option<DateTime<Utc>> {
        Self::extract_timestamp(claims, "iat")
    }

    /// Normalize provider name from issuer claim if available
    fn normalize_provider(provider: &str, claims: &Value) -> String {
        if let Some(issuer) = claims.get("iss").and_then(|v| v.as_str()) {
            debug!("Found issuer claim: {issuer}");

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
    use crate::utils::apple::{AppleUserInfo, AppleUserName};
    use base64::Engine as _;
    use chrono::Utc;
    use serde_json::json;

    fn minimal_id_token(sub: &str) -> String {
        // JWT with only 'sub' claim, base64-encoded header and payload, signature ignored
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\"}");
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(format!(r#"{{"sub":"{sub}"}}"#).as_bytes());
        format!("{header}.{payload}.ignored")
    }

    #[test]
    fn test_extract_subject_success() {
        let claims = json!({
            "sub": "12345",
            "email": "test@example.com"
        });

        assert_eq!(IdTokenProcessor::extract_subject(&claims).unwrap(), "12345");
    }

    #[test]
    fn test_extract_subject_missing() {
        let claims = json!({
            "email": "test@example.com"
        });

        assert!(IdTokenProcessor::extract_subject(&claims).is_err());
    }

    #[test]
    fn test_extract_name_google_format() {
        let claims = json!({
            "name": "John Doe"
        });

        assert_eq!(
            IdTokenProcessor::extract_name(&claims),
            Some("John Doe".to_string())
        );
    }

    #[test]
    fn test_extract_name_apple_format() {
        let claims = json!({
            "given_name": "John",
            "family_name": "Doe"
        });

        assert_eq!(
            IdTokenProcessor::extract_name(&claims),
            Some("John Doe".to_string())
        );
    }

    #[test]
    fn test_extract_name_missing() {
        let claims = json!({
            "sub": "12345",
            "email": "test@example.com"
        });

        assert_eq!(IdTokenProcessor::extract_name(&claims), None);
    }

    #[test]
    fn test_process_id_token_with_apple_info() {
        let id_token_str = minimal_id_token("apple-sub-123");
        let refresh_token = Some("refresh123".to_string());
        let expires_at = Utc::now() + chrono::Duration::hours(1);
        let apple_user_info = AppleUserInfo {
            name: AppleUserName {
                first_name: Some("Jane".to_string()),
                last_name: Some("Doe".to_string()),
            },
            email: Some("jane.doe@apple.com".to_string()),
        };

        let result = IdTokenProcessor::process_id_token(
            "apple",
            Some(&id_token_str),
            refresh_token,
            expires_at,
            Some(&apple_user_info),
        )
        .expect("OAuth result should be created");

        assert_eq!(result.email.unwrap(), "jane.doe@apple.com");
        assert_eq!(result.name.unwrap(), "Jane Doe");
        assert_eq!(result.provider, "apple");
        assert_eq!(result.provider_id, "apple-sub-123");
        assert!(result.id_token.is_some());
        assert!(result.refresh_token.is_some());
    }
}
