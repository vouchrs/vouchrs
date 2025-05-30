// Config-driven OAuth implementation using provider configurations from settings
// Supports dynamic discovery endpoints and customizable provider configurations

use std::collections::HashMap;
use std::env;
use crate::models::{AppleUserInfo};
use crate::settings::{ProviderSettings, JwtSigningConfig, VouchrsSettings};
use crate::utils::logging::LoggingHelper;
use chrono::{Utc};
use serde::{Deserialize, Serialize};
use p256::ecdsa::{SigningKey, Signature, signature::Signer}; 
use p256::pkcs8::DecodePrivateKey;
use base64::{Engine as _, engine::general_purpose}; 
use log;

// Add missing error type
#[derive(Debug)]
pub enum OAuthError {
    Configuration(String),
    Network(String),
    InvalidResponse(String),
}

impl std::fmt::Display for OAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OAuthError::Configuration(msg) => write!(f, "Configuration error: {}", msg),
            OAuthError::Network(msg) => write!(f, "Network error: {}", msg),
            OAuthError::InvalidResponse(msg) => write!(f, "Invalid response: {}", msg),
        }
    }
}

impl std::error::Error for OAuthError {}

#[derive(Debug, Serialize, Deserialize)]
struct AppleJwtClaims {
    iss: String,    // Team ID
    iat: i64,       // Issued at time
    exp: i64,       // Expiration time
    aud: String,    // Audience (always "https://appleid.apple.com")
    sub: String,    // Client ID
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    id_token: Option<String>,
    token_type: String,
    expires_in: Option<u64>,
    scope: Option<String>,
    user: Option<AppleUserInfo>, // Apple-specific user info field
}

// Runtime provider configuration with resolved endpoints
#[derive(Debug, Clone)]
pub struct RuntimeProvider {
    pub settings: ProviderSettings,
    pub auth_url: String,
    pub token_url: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

impl RuntimeProvider {
    pub async fn from_settings(settings: ProviderSettings) -> Result<Self, String> {
        // Use the new getter methods instead of direct environment variable access
        let client_id = settings.get_client_id();
        let client_secret = settings.get_client_secret();

        // Resolve endpoints from discovery URL or use direct URLs
        let (auth_url, token_url) = if let Some(ref discovery_url) = settings.discovery_url {
            Self::resolve_from_discovery(discovery_url).await?
        } else {
            let auth_url = settings.authorization_endpoint.clone()
                .ok_or_else(|| format!("Provider {} missing authorization_endpoint", settings.name))?;
            let token_url = settings.token_endpoint.clone()
                .ok_or_else(|| format!("Provider {} missing token_endpoint", settings.name))?;
            (auth_url, token_url)
        };

        Ok(RuntimeProvider {
            settings,
            auth_url,
            token_url,
            client_id,
            client_secret,
        })
    }

    async fn resolve_from_discovery(discovery_url: &str) -> Result<(String, String), String> {
        let resp = reqwest::get(discovery_url).await.map_err(|e| e.to_string())?;
        let doc: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        let auth_url = doc["authorization_endpoint"].as_str()
            .ok_or_else(|| "Missing authorization_endpoint in discovery document".to_string())?
            .to_string();
        let token_url = doc["token_endpoint"].as_str()
            .ok_or_else(|| "Missing token_endpoint in discovery document".to_string())?
            .to_string();
        Ok((auth_url, token_url))
    }

    pub fn is_configured(&self) -> bool {
        self.client_id.is_some() && 
        (self.client_secret.is_some() || self.settings.jwt_signing.is_some())
    }
}

// Config-driven OAuth configuration
#[derive(Clone)]
pub struct OAuthConfig {
    pub providers: HashMap<String, RuntimeProvider>,
    pub redirect_base_url: String,
    http_client: reqwest::Client,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl OAuthConfig {
    pub fn new() -> Self {
        let redirect_base_url = env::var("REDIRECT_BASE_URL")
            .unwrap_or_else(|_| "http://localhost:8080".to_string());

        Self {
            providers: HashMap::new(),
            redirect_base_url,
            http_client: reqwest::Client::new(),
        }
    }

    /// Initialize providers from settings
    pub async fn initialize_from_settings(&mut self, settings: &VouchrsSettings) -> Result<(), String> {
        LoggingHelper::log_oauth_provider_initialization();
        
        for provider_settings in &settings.providers {
            if !provider_settings.enabled {
                LoggingHelper::log_oauth_provider_disabled(&provider_settings.name);
                continue;
            }

            match RuntimeProvider::from_settings(provider_settings.clone()).await {
                Ok(runtime_provider) => {
                    if runtime_provider.is_configured() {
                        LoggingHelper::log_oauth_provider_configured(
                            provider_settings.display_name.as_deref().unwrap_or(&provider_settings.name),
                            &provider_settings.name
                        );
                        self.providers.insert(provider_settings.name.clone(), runtime_provider);
                    } else {
                        LoggingHelper::log_oauth_provider_not_configured(
                            provider_settings.display_name.as_deref().unwrap_or(&provider_settings.name)
                        );
                    }
                },
                Err(e) => {
                    log::error!("❌ Failed to initialize provider {}: {}", 
                        provider_settings.name, e);
                }
            }
        }        
        if self.providers.is_empty() {
            return Err("No OAuth providers are configured. Please configure at least one provider in Settings.toml and set the required environment variables.".to_string());
        } else {
            let provider_names: Vec<_> = self.providers.keys().collect();
            LoggingHelper::log_oauth_providers_summary(&provider_names);
        }

        Ok(())
    }

    pub fn get_client_configured(&self, provider: &str) -> bool {
        self.providers.get(provider)
            .map(|p| p.is_configured())
            .unwrap_or(false)
    }

    pub async fn get_auth_url(&self, provider: &str, state: &str) -> Result<String, String> {
        let runtime_provider = self.providers.get(provider)
            .ok_or_else(|| format!("Provider {} not configured", provider))?;

        // Get client ID using the new getter method
        let client_id = runtime_provider.settings.get_client_id()
            .ok_or_else(|| format!("Client ID not configured for provider {}", provider))?;

        // Build authorization URL
        let redirect_uri = format!("{}/oauth2/callback", self.redirect_base_url);
        let scopes = runtime_provider.settings.scopes.join(" ");
        
        // Start with base parameters
        let mut url = url::Url::parse(&runtime_provider.auth_url).map_err(|e| e.to_string())?;
        url.query_pairs_mut()
            .append_pair("client_id", &client_id)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", &scopes)
            .append_pair("state", state);
        
        // Add provider-specific extra parameters
        for (key, value) in &runtime_provider.settings.extra_auth_params {
            url.query_pairs_mut().append_pair(key, value);
        }
        
        LoggingHelper::log_oauth_url_built(provider, &scopes, &runtime_provider.settings.extra_auth_params);
        
        Ok(url.to_string())
    }

    fn generate_apple_client_secret(jwt_config: &JwtSigningConfig, client_id: &str) -> Result<String, String> {
        // Use the new getter methods instead of direct environment variable access
        let team_id = jwt_config.get_team_id()
            .ok_or_else(|| "Team ID not configured for Apple provider".to_string())?;
        let key_id = jwt_config.get_key_id()
            .ok_or_else(|| "Key ID not configured for Apple provider".to_string())?;
        let private_key_path = jwt_config.get_private_key_path()
            .ok_or_else(|| "Private key path not configured for Apple provider".to_string())?;

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
        let now = chrono::Utc::now();
        let exp = now + chrono::Duration::minutes(5);
        
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

    /// Exchange OAuth authorization code for OAuth tokens
    /// This manually handles the token exchange to properly capture ID tokens
    /// Returns (OAuthTokens, Option<AppleUserInfo>) for Apple user info fallback
    pub async fn exchange_code_for_session_data(
        &self,
        provider: &str,
        code: &str,
    ) -> Result<(Option<String>, Option<String>, chrono::DateTime<Utc>, Option<crate::models::AppleUserInfo>), String> {
        let runtime_provider = self.providers.get(provider)
            .ok_or_else(|| format!("Provider {} not configured", provider))?;

        // Prepare token exchange request
        let redirect_uri = format!("{}/oauth2/callback", self.redirect_base_url);
        let mut params = HashMap::new();
        params.insert("grant_type", "authorization_code");
        params.insert("code", code);
        params.insert("redirect_uri", &redirect_uri);

        // Handle client credentials based on provider configuration
        let client_secret;
        let client_id = runtime_provider.settings.get_client_id()
            .ok_or_else(|| format!("Client ID not configured for provider {}", provider))?;
        
        params.insert("client_id", &client_id);

        if let Some(ref secret) = runtime_provider.client_secret {
            // Regular OAuth with client secret
            params.insert("client_secret", secret);
        } else if let Some(ref jwt_config) = runtime_provider.settings.jwt_signing {
            // JWT signing (Apple)
            client_secret = Self::generate_apple_client_secret(jwt_config, &client_id)?;
            params.insert("client_secret", &client_secret);
        } else {
            return Err("No client secret or JWT signing configuration for provider".to_string());
        }

        // Make token exchange request
        LoggingHelper::log_token_exchange_start(provider);
        let response = self.http_client
            .post(&runtime_provider.token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| format!("Failed to exchange code for token: {}", e))?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(format!("Token exchange failed with status {}: {}", status, error_text));
        }
        
        // Get the raw response text for debugging
        let response_text = response.text().await
            .map_err(|e| format!("Failed to read response text: {}", e))?;
        
        // Log the raw token response for debugging (especially for Apple)
        if provider == "apple" {
            LoggingHelper::log_apple_token_response_raw(&response_text);
        } else {
            LoggingHelper::log_token_response_raw(provider, &response_text);
        }
        
        let token_response: TokenResponse = serde_json::from_str(&response_text)
            .map_err(|e| format!("Failed to parse token response: {}", e))?;

        // Calculate token expiration
        let expires_at = if let Some(expires_in) = token_response.expires_in {
            Utc::now() + chrono::Duration::seconds(expires_in as i64)
        } else {
            // Default to 1 hour if no expiration provided
            Utc::now() + chrono::Duration::hours(1)
        };

        // Log detailed information about what we extracted
        LoggingHelper::log_token_exchange_summary(
            provider,
            token_response.access_token.len(),
            token_response.refresh_token.as_ref(),
            token_response.id_token.as_ref(),
            &token_response.token_type,
            token_response.scope.as_ref(),
            token_response.user.is_some()
        );

        let id_token = token_response.id_token;
        let refresh_token = token_response.refresh_token;
        let apple_user_info = token_response.user;
        Ok((id_token, refresh_token, expires_at, apple_user_info))
    }

    pub fn get_signout_url(&self, provider: &str) -> Option<String> {
        self.providers.get(provider)
            .and_then(|p| p.settings.signout_url.clone())
    }

    /// Get list of enabled provider names
    pub fn get_enabled_providers(&self) -> Vec<&str> {
        self.providers.keys().map(|s| s.as_str()).collect()
    }

    /// Get provider display name
    pub fn get_provider_display_name(&self, provider: &str) -> Option<&str> {
        self.providers.get(provider)
            .and_then(|p| p.settings.display_name.as_deref())
    }
}

pub struct OAuthProvider {
    pub name: String,
    pub client_id: String,
    pub client_secret: String,
    // ... other fields ...
}

impl OAuthProvider {
    pub fn from_settings(settings: &ProviderSettings) -> Result<Self, OAuthError> {
        // Use the new getter methods instead of direct field access
        let client_id = settings.get_client_id()
            .ok_or_else(|| OAuthError::Configuration(
                format!("Client ID not configured for provider '{}'", settings.name)
            ))?;
            
        let client_secret = settings.get_client_secret()
            .ok_or_else(|| OAuthError::Configuration(
                format!("Client secret not configured for provider '{}'", settings.name)
            ))?;
        
        Ok(Self {
            name: settings.name.clone(),
            client_id,
            client_secret,
        })
    }
}
