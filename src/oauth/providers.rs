//! Provider-specific OAuth logic
//!
//! This module contains provider-specific implementations for OAuth flows,
//! including configuration, endpoints, and token exchange logic.

use crate::oauth::service::OAuthError;
use crate::settings::{ProviderSettings, VouchrsSettings};
use anyhow::Result;
use std::collections::HashMap;

/// Provider-specific OAuth configuration
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub name: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub scopes: Vec<String>,
}

/// OAuth provider manager
pub struct OAuthProviderManager {
    providers: HashMap<String, ProviderConfig>,
}

impl OAuthProviderManager {
    /// Create a new provider manager from settings
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Provider configuration is invalid
    /// - Required provider settings are missing
    /// - Unsupported provider is configured
    pub fn new(settings: &VouchrsSettings) -> Result<Self, OAuthError> {
        let mut providers = HashMap::new();

        for provider_settings in &settings.providers {
            let config = Self::create_provider_config(provider_settings)?;
            providers.insert(config.name.clone(), config);
        }

        Ok(Self { providers })
    }

    /// Get provider configuration by name
    #[must_use]
    pub fn get_provider(&self, name: &str) -> Option<&ProviderConfig> {
        self.providers.get(name)
    }

    /// Create provider configuration from settings
    fn create_provider_config(settings: &ProviderSettings) -> Result<ProviderConfig, OAuthError> {
        let client_id = settings.get_client_id().ok_or_else(|| {
            OAuthError::Configuration(format!("Missing client_id for provider {}", settings.name))
        })?;

        let client_secret = settings.get_client_secret();

        // Set default endpoints based on provider name
        let (auth_endpoint, token_endpoint, scopes) = match settings.name.as_str() {
            "google" => (
                "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
                "https://oauth2.googleapis.com/token".to_string(),
                vec![
                    "openid".to_string(),
                    "email".to_string(),
                    "profile".to_string(),
                ],
            ),
            "apple" => (
                "https://appleid.apple.com/auth/authorize".to_string(),
                "https://appleid.apple.com/auth/token".to_string(),
                vec![
                    "openid".to_string(),
                    "email".to_string(),
                    "name".to_string(),
                ],
            ),
            "microsoft" => (
                "https://login.microsoftonline.com/common/oauth2/v2.0/authorize".to_string(),
                "https://login.microsoftonline.com/common/oauth2/v2.0/token".to_string(),
                vec![
                    "openid".to_string(),
                    "email".to_string(),
                    "profile".to_string(),
                ],
            ),
            _ => {
                return Err(OAuthError::Configuration(format!(
                    "Unsupported provider: {}",
                    settings.name
                )))
            }
        };

        Ok(ProviderConfig {
            name: settings.name.clone(),
            client_id,
            client_secret,
            authorization_endpoint: auth_endpoint,
            token_endpoint,
            scopes,
        })
    }

    /// Exchange authorization code for tokens
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Provider is not configured
    /// - HTTP request fails
    /// - Token response is invalid
    pub fn exchange_code_for_tokens(
        &self,
        provider_name: &str,
        _authorization_code: &str,
        _redirect_uri: &str,
    ) -> Result<TokenResponse, OAuthError> {
        let _provider = self
            .get_provider(provider_name)
            .ok_or_else(|| OAuthError::Provider(format!("Unknown provider: {provider_name}")))?;

        // Note: Token exchange functionality has been implemented in src/oauth.rs
        // This method is kept for compatibility but the main implementation is elsewhere
        Err(OAuthError::Configuration(
            "Token exchange should use the main OAuth implementation in src/oauth.rs".to_string(),
        ))
    }
}

/// OAuth token response
#[derive(Debug, Clone)]
pub struct TokenResponse {
    pub access_token: String,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
    pub token_type: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::ProviderSettings;

    #[test]
    fn test_provider_config_creation() {
        let provider_settings = ProviderSettings {
            name: "google".to_string(),
            client_id: Some("test_client_id".to_string()),
            client_secret: Some("test_client_secret".to_string()),
            ..Default::default()
        };

        let config = OAuthProviderManager::create_provider_config(&provider_settings).unwrap();
        assert_eq!(config.name, "google");
        assert_eq!(config.client_id, "test_client_id");
        assert_eq!(config.client_secret, Some("test_client_secret".to_string()));
    }
}
