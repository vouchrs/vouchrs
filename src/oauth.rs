// Config-driven OAuth implementation using provider configurations from settings
// Supports dynamic discovery endpoints and customizable provider configurations

use crate::models::VouchrsSession;
use crate::settings::{ProviderSettings, VouchrsSettings};
use crate::utils::apple_utils;
use crate::utils::logging::LoggingHelper;
use actix_web::HttpResponse;
use chrono::Utc;
use log;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::env;

/// Error types for OAuth operations
#[derive(Debug)]
pub enum OAuthError {
    Configuration(String),
    Network(String),
    InvalidResponse(String),
}

/// OAuth callback structure for handling responses from OAuth providers
#[derive(Deserialize, Debug)]
pub struct OAuthCallback {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub user: Option<serde_json::Value>, // Apple sends user info in form POST on first login
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OAuthState {
    pub state: String,
    pub provider: String,
    pub redirect_url: Option<String>,
}

// Session Management Structures
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OAuthTokens {
    pub token_type: String,
    pub scope: Option<String>,
}

impl std::fmt::Display for OAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OAuthError::Configuration(msg) => write!(f, "Configuration error: {msg}"),
            OAuthError::Network(msg) => write!(f, "Network error: {msg}"),
            OAuthError::InvalidResponse(msg) => write!(f, "Invalid response: {msg}"),
        }
    }
}

impl std::error::Error for OAuthError {}

#[derive(Debug, Serialize, Deserialize)]
struct AppleJwtClaims {
    iss: String, // Team ID
    iat: i64,    // Issued at time
    exp: i64,    // Expiration time
    aud: String, // Audience (always "https://appleid.apple.com")
    sub: String, // Client ID
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    refresh_token: Option<String>,
    id_token: Option<String>,
    token_type: String,
    expires_in: Option<u64>,
    scope: Option<String>,
    user: Option<apple_utils::AppleUserInfo>, // Apple-specific user info field
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
    /// Creates a `RuntimeProvider` from settings
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Discovery URL cannot be resolved
    /// - Required configuration is missing
    /// - Network errors occur during discovery
    pub async fn from_settings(settings: ProviderSettings) -> Result<Self, String> {
        // Use the new getter methods instead of direct environment variable access
        let client_id = settings.get_client_id();
        let client_secret = settings.get_client_secret();

        // Resolve endpoints from discovery URL or use direct URLs
        let (auth_url, token_url) = if let Some(ref discovery_url) = settings.discovery_url {
            Self::resolve_from_discovery(discovery_url).await?
        } else {
            let auth_url = settings.authorization_endpoint.clone().ok_or_else(|| {
                format!("Provider {} missing authorization_endpoint", settings.name)
            })?;
            let token_url = settings
                .token_endpoint
                .clone()
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

    /// Resolve authorization and token endpoints from discovery URL
    /// 
    /// # Errors
    /// 
    /// Returns an error if:
    /// - Network request to discovery URL fails
    /// - Response cannot be parsed as JSON
    /// - Required endpoints are missing from discovery document
    async fn resolve_from_discovery(discovery_url: &str) -> Result<(String, String), String> {
        let resp = reqwest::get(discovery_url)
            .await
            .map_err(|e| e.to_string())?;
        let doc: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        let auth_url = doc["authorization_endpoint"]
            .as_str()
            .ok_or_else(|| "Missing authorization_endpoint in discovery document".to_string())?
            .to_string();
        let token_url = doc["token_endpoint"]
            .as_str()
            .ok_or_else(|| "Missing token_endpoint in discovery document".to_string())?
            .to_string();
        Ok((auth_url, token_url))
    }

    /// Check if the provider is properly configured
    #[must_use]
    pub fn is_configured(&self) -> bool {
        self.client_id.is_some()
            && (self.client_secret.is_some() || self.settings.jwt_signing.is_some())
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
    /// Create a new OAuth configuration
    #[must_use]
    pub fn new() -> Self {
        let redirect_base_url =
            env::var("REDIRECT_BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());

        Self {
            providers: HashMap::new(),
            redirect_base_url,
            http_client: reqwest::Client::new(),
        }
    }

    /// Initialize providers from settings
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Provider validation fails for any enabled provider
    /// - Required environment variables are missing for enabled providers
    /// - Provider configuration is invalid or incomplete
    /// - No providers are successfully configured
    pub async fn initialize_from_settings(
        &mut self,
        settings: &VouchrsSettings,
    ) -> Result<(), String> {
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
                            provider_settings
                                .display_name
                                .as_deref()
                                .unwrap_or(&provider_settings.name),
                            &provider_settings.name,
                        );
                        self.providers
                            .insert(provider_settings.name.clone(), runtime_provider);
                    } else {
                        LoggingHelper::log_oauth_provider_not_configured(
                            provider_settings
                                .display_name
                                .as_deref()
                                .unwrap_or(&provider_settings.name),
                        );
                    }
                }
                Err(e) => {
                    log::error!(
                        "❌ Failed to initialize provider {}: {e}",
                        provider_settings.name
                    );
                }
            }
        }
        if self.providers.is_empty() {
            return Err("No OAuth providers are configured. Please configure at least one provider in Settings.toml and set the required environment variables.".to_string());
        }
        let provider_names: Vec<_> = self.providers.keys().collect();
        LoggingHelper::log_oauth_providers_summary(&provider_names);

        Ok(())
    }

    /// Check if a provider's client is configured
    #[must_use]
    pub fn get_client_configured(&self, provider: &str) -> bool {
        self.providers
            .get(provider)
            .is_some_and(RuntimeProvider::is_configured)
    }

    /// Get the authorization URL for a provider
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The specified provider is not configured
    /// - The client ID is not configured for the provider
    /// - The authorization URL is malformed
    pub async fn get_auth_url(&self, provider: &str, state: &str) -> Result<String, String> {
        let runtime_provider = self
            .providers
            .get(provider)
            .ok_or_else(|| format!("Provider {provider} not configured"))?;

        // Get client ID using the new getter method
        let client_id = runtime_provider
            .settings
            .get_client_id()
            .ok_or_else(|| format!("Client ID not configured for provider {provider}"))?;

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

        LoggingHelper::log_oauth_url_built(
            provider,
            &scopes,
            &runtime_provider.settings.extra_auth_params,
        );

        Ok(url.to_string())
    }

    /// Exchange OAuth authorization code for OAuth tokens
    /// This manually handles the token exchange to properly capture ID tokens
    /// Returns (`id_token`, `refresh_token`, `expires_at`, `Option<AppleUserInfo>`) for Apple user info fallback
    /// 
    /// # Errors
    /// 
    /// Returns an error if:
    /// - Provider is not configured
    /// - Client credentials are missing
    /// - Token exchange request fails
    /// - Response parsing fails
    pub async fn exchange_code_for_session_data(
        &self,
        provider: &str,
        code: &str,
    ) -> Result<
        (
            Option<String>,
            Option<String>,
            chrono::DateTime<Utc>,
            Option<apple_utils::AppleUserInfo>,
        ),
        String,
    > {
        let runtime_provider = self
            .providers
            .get(provider)
            .ok_or_else(|| format!("Provider {provider} not configured"))?;

        // Prepare token exchange request
        let redirect_uri = format!("{}/oauth2/callback", self.redirect_base_url);
        let mut params = HashMap::new();
        params.insert("grant_type", "authorization_code");
        params.insert("code", code);
        params.insert("redirect_uri", &redirect_uri);

        // Handle client credentials based on provider configuration
        let client_secret;
        let client_id = runtime_provider
            .settings
            .get_client_id()
            .ok_or_else(|| format!("Client ID not configured for provider {provider}"))?;

        params.insert("client_id", &client_id);

        if let Some(ref secret) = runtime_provider.client_secret {
            // Regular OAuth with client secret
            params.insert("client_secret", secret);
        } else if let Some(ref jwt_config) = runtime_provider.settings.jwt_signing {
            // JWT signing (Apple)
            client_secret =
                crate::utils::apple_utils::generate_apple_client_secret(jwt_config, &client_id)?;
            params.insert("client_secret", &client_secret);
        } else {
            return Err("No client secret or JWT signing configuration for provider".to_string());
        }

        // Make token exchange request
        LoggingHelper::log_token_exchange_start(provider);
        let response = self
            .http_client
            .post(&runtime_provider.token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| format!("Failed to exchange code for token: {e}"))?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(format!(
                "Token exchange failed with status {status}: {error_text}"
            ));
        }

        // Get the raw response text for debugging
        let response_text = response
            .text()
            .await
            .map_err(|e| format!("Failed to read response text: {e}"))?;

        // Log the raw token response for debugging (especially for Apple)
        if provider == "apple" {
            LoggingHelper::log_apple_token_response_raw(&response_text);
        } else {
            LoggingHelper::log_token_response_raw(provider, &response_text);
        }

        let token_response: TokenResponse = serde_json::from_str(&response_text)
            .map_err(|e| format!("Failed to parse token response: {e}"))?;

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
            token_response.refresh_token.as_ref(),
            token_response.id_token.as_ref(),
            &token_response.token_type,
            token_response.scope.as_ref(),
            token_response.user.is_some(),
        );

        let id_token = token_response.id_token;
        let refresh_token = token_response.refresh_token;
        let apple_user_info = token_response.user;
        Ok((id_token, refresh_token, expires_at, apple_user_info))
    }

    /// Get the signout URL for a provider
    #[must_use]
    pub fn get_signout_url(&self, provider: &str) -> Option<String> {
        self.providers
            .get(provider)
            .and_then(|p| p.settings.signout_url.clone())
    }

    /// Get list of enabled provider names
    #[must_use]
    pub fn get_enabled_providers(&self) -> Vec<&str> {
        self.providers.keys().map(std::string::String::as_str).collect()
    }

    /// Get provider display name
    #[must_use]
    pub fn get_provider_display_name(&self, provider: &str) -> Option<&str> {
        self.providers
            .get(provider)
            .and_then(|p| p.settings.display_name.as_deref())
    }
}

pub struct OAuthProvider {
    pub name: String,
    pub client_id: String,
    pub client_secret: String,
}

impl OAuthProvider {
    /// Create an `OAuthProvider` from settings
    /// 
    /// # Errors
    /// 
    /// Returns an error if:
    /// - Client ID is not configured
    /// - Client secret is not configured
    pub fn from_settings(settings: &ProviderSettings) -> Result<Self, OAuthError> {
        // Use the new getter methods instead of direct field access
        let client_id = settings.get_client_id().ok_or_else(|| {
            OAuthError::Configuration(format!(
                "Client ID not configured for provider '{}'",
                settings.name
            ))
        })?;

        let client_secret = settings.get_client_secret().ok_or_else(|| {
            OAuthError::Configuration(format!(
                "Client secret not configured for provider '{}'",
                settings.name
            ))
        })?;

        Ok(Self {
            name: settings.name.clone(),
            client_id,
            client_secret,
        })
    }
}

// Static HTTP client for making token refresh requests
static CLIENT: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(reqwest::Client::new);

/// Check if tokens need refresh and refresh them if necessary
/// 
/// # Errors
/// 
/// Returns an `HttpResponse` error if:
/// - Tokens are expired and no refresh token is available
/// - Token refresh fails
pub async fn check_and_refresh_tokens(
    mut session: VouchrsSession,
    oauth_config: &OAuthConfig,
    provider: &str,
) -> Result<VouchrsSession, HttpResponse> {
    // Check if tokens need refresh (within 5 minutes of expiry)
    let now = chrono::Utc::now();
    let buffer_time = chrono::Duration::minutes(5);
    if session.expires_at > now + buffer_time {
        return Ok(session);
    }

    // Attempt to refresh tokens
    let refresh_token = session.refresh_token.as_ref().ok_or_else(|| {
        HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "unauthorized",
            "message": "OAuth tokens expired and no refresh token available. Please re-authenticate."
        }))
    })?;

    // Call refresh_oauth_tokens and update session fields
    match refresh_oauth_tokens(refresh_token, oauth_config, provider).await {
        Ok((new_id_token, new_refresh_token, new_expires_at)) => {
            session.id_token = new_id_token;
            session.refresh_token = new_refresh_token;
            session.expires_at = new_expires_at;
            Ok(session)
        }
        Err(err) => Err(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "token_refresh_failed",
            "message": format!("Failed to refresh OAuth tokens: {err}")
        }))),
    }
}

/// Refresh OAuth tokens using the refresh token
/// 
/// # Errors
/// 
/// Returns an error if:
/// - Provider is not configured
/// - Client credentials are missing or cannot be generated
/// - Token refresh request fails
/// - Response parsing fails
pub async fn refresh_oauth_tokens(
    refresh_token: &str,
    oauth_config: &OAuthConfig,
    provider: &str,
) -> Result<
    (
        Option<String>,
        Option<String>,
        chrono::DateTime<chrono::Utc>,
    ),
    String,
> {
    // Get provider configuration
    let runtime_provider = oauth_config
        .providers
        .get(provider)
        .ok_or_else(|| format!("Provider {provider} not configured"))?;

    let client_id = runtime_provider
        .client_id
        .as_ref()
        .ok_or_else(|| format!("Client ID not configured for provider {provider}"))?;

    // Handle client credentials based on provider configuration
    let client_secret = if let Some(ref secret) = runtime_provider.client_secret {
        secret.clone()
    } else if let Some(ref jwt_config) = runtime_provider.settings.jwt_signing {
        // Generate JWT client secret for Apple using apple_utils
        apple_utils::generate_apple_client_secret_for_refresh(
            jwt_config,
            &runtime_provider.settings,
        )
        .map_err(|e| format!("Failed to generate client secret: {e}"))?
    } else {
        return Err(format!(
            "No client secret or JWT signing configuration for provider {provider}"
        ));
    };

    let params = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id.as_str()),
        ("client_secret", client_secret.as_str()),
    ];

    let response = CLIENT
        .post(&runtime_provider.token_url)
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {e}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(format!(
            "Token refresh failed with status {status}: {error_text}"
        ));
    }

    // Parse token response extracting id_token, refresh_token, expires_at
    let token_response: Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse token response: {e}"))?;

    let expires_in = token_response["expires_in"].as_u64().unwrap_or(3600); // Default to 1 hour

    let new_refresh_token = token_response["refresh_token"]
        .as_str()
        .map(ToString::to_string);

    let new_id_token = token_response["id_token"].as_str().map(ToString::to_string);

    let new_expires_at = chrono::Utc::now() + chrono::Duration::seconds(expires_in as i64);

    Ok((new_id_token, new_refresh_token, new_expires_at))
}
