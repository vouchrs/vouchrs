//! OAuth configuration module
//!
//! This module provides OAuth configuration management including provider
//! configuration, runtime settings, and token exchange functionality.

use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::time::Duration;

use actix_web::HttpResponse;
use chrono::Utc;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::RwLock;

use crate::models::VouchrsSession;
use crate::settings::{ProviderSettings, VouchrsSettings};
use crate::utils::apple;

// Static HTTP client for making OAuth and JWT validation requests
static CLIENT: std::sync::LazyLock<reqwest::Client> = std::sync::LazyLock::new(|| {
    reqwest::Client::builder()
        .pool_max_idle_per_host(10)
        .pool_idle_timeout(Duration::from_secs(90))
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .build()
        .expect("Failed to create HTTP client")
});

// ============================================================================
// Error Types
// ============================================================================

/// Error types for OAuth operations
#[derive(Debug)]
pub enum OAuthError {
    Configuration(String),
    Network(String),
    InvalidResponse(String),
}

impl std::fmt::Display for OAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Configuration(msg) => write!(f, "Configuration error: {msg}"),
            Self::Network(msg) => write!(f, "Network error: {msg}"),
            Self::InvalidResponse(msg) => write!(f, "Invalid response: {msg}"),
        }
    }
}

impl std::error::Error for OAuthError {}

// ============================================================================
// Core Data Structures
// ============================================================================

/// OAuth tokens structure for session management
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OAuthTokens {
    pub token_type: String,
    pub scope: Option<String>,
}

// ============================================================================
// Internal Structures
// ============================================================================

/// Apple JWT claims structure for client secret generation
#[derive(Debug, Serialize, Deserialize)]
struct AppleJwtClaims {
    iss: String, // Team ID
    iat: i64,    // Issued at time
    exp: i64,    // Expiration time
    aud: String, // Audience (always "https://appleid.apple.com")
    sub: String, // Client ID
}

/// Token response structure from OAuth providers
#[derive(Debug, Deserialize)]
struct TokenResponse {
    refresh_token: Option<String>,
    id_token: Option<String>,
    token_type: String,
    expires_in: Option<u64>,
    user: Option<apple::AppleUserInfo>, // Apple-specific user info field
}

// ============================================================================
// Provider Configuration
// ============================================================================

/// Runtime provider configuration with resolved endpoints and cached encoded values
#[derive(Debug, Clone)]
pub struct RuntimeProvider {
    pub settings: ProviderSettings,
    pub auth_url: String,
    pub token_url: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    // Cached encoded values for performance optimization
    pub encoded_client_id: Option<String>,
    pub encoded_scopes: String,
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

        Ok(Self {
            settings: settings.clone(),
            auth_url,
            token_url,
            client_id: client_id.clone(),
            client_secret,
            // Pre-compute encoded values for performance optimization
            encoded_client_id: client_id.map(|id| urlencoding::encode(&id).into_owned()),
            encoded_scopes: {
                let total_scope_len: usize = settings.scopes.iter().map(String::len).sum();
                let scope_separators = settings.scopes.len().saturating_sub(1);
                let mut scopes = String::with_capacity(total_scope_len + scope_separators);
                for (i, scope) in settings.scopes.iter().enumerate() {
                    if i > 0 {
                        scopes.push(' ');
                    }
                    scopes.push_str(scope);
                }
                urlencoding::encode(&scopes).into_owned()
            },
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
        let resp = CLIENT
            .get(discovery_url)
            .send()
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
    pub const fn is_configured(&self) -> bool {
        self.client_id.is_some()
            && (self.client_secret.is_some() || self.settings.jwt_signing.is_some())
    }
}

// ============================================================================
// Type Aliases
// ============================================================================

/// Result type for token exchange operations
/// Returns (`id_token`, `refresh_token`, `expires_at`, `apple_user_info_fallback`)
type TokenExchangeResult = Result<
    (
        Option<String>,
        Option<String>,
        chrono::DateTime<Utc>,
        Option<apple::AppleUserInfo>,
    ),
    String,
>;

// ============================================================================
// OAuth Configuration
// ============================================================================

/// Config-driven OAuth configuration with multiple provider support
#[derive(Clone)]
pub struct OAuthConfig {
    pub providers: HashMap<String, RuntimeProvider>,
    pub redirect_base_url: String,
    // Cached encoded redirect URI for performance optimization
    pub encoded_redirect_uri: String,
    jwt_validator: Arc<RwLock<Option<crate::oauth::jwt_validation::JwtValidator>>>,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl OAuthConfig {
    /// Create a new OAuth configuration
    ///
    /// # Panics
    ///
    /// Panics if the HTTP client cannot be created due to invalid configuration.
    #[must_use]
    pub fn new() -> Self {
        let redirect_base_url =
            env::var("REDIRECT_BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());

        // Pre-compute encoded redirect URI with callback path for performance optimization
        let redirect_uri_with_callback = format!("{redirect_base_url}/auth/oauth2/callback");
        let encoded_redirect_uri = urlencoding::encode(&redirect_uri_with_callback).to_string();

        Self {
            providers: HashMap::new(),
            redirect_base_url,
            encoded_redirect_uri,
            jwt_validator: Arc::new(RwLock::new(None)), // Will be initialized when needed
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
        info!("🔧 Initializing OAuth providers from configuration...");

        for provider_settings in &settings.providers {
            if !provider_settings.enabled {
                info!(
                    "⏭️  Provider {} is disabled, skipping",
                    provider_settings.name
                );
                continue;
            }

            match RuntimeProvider::from_settings(provider_settings.clone()).await {
                Ok(runtime_provider) => {
                    if runtime_provider.is_configured() {
                        info!(
                            "✅ {} OAuth2 configured ({})",
                            provider_settings
                                .display_name
                                .as_deref()
                                .unwrap_or(&provider_settings.name),
                            provider_settings.name
                        );
                        self.providers
                            .insert(provider_settings.name.clone(), runtime_provider);
                    } else {
                        info!(
                            "❌ {} OAuth2 not configured - missing environment variables",
                            provider_settings
                                .display_name
                                .as_deref()
                                .unwrap_or(&provider_settings.name)
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
        info!("🎯 Configured OAuth providers: {provider_names:?}");

        Ok(())
    }

    /// Get or initialize JWT validator
    async fn get_jwt_validator(&self) -> crate::oauth::jwt_validation::JwtValidator {
        let mut jwt_validator_guard = self.jwt_validator.write().await;
        if jwt_validator_guard.is_none() {
            *jwt_validator_guard = Some(crate::oauth::jwt_validation::JwtValidator::new());
            info!("🔐 Initialized JWT validator for ID token validation");
        }
        jwt_validator_guard.as_ref().unwrap().clone()
    }

    /// Check if any provider has JWT validation enabled
    #[must_use]
    pub fn has_jwt_validation_enabled(&self) -> bool {
        self.providers
            .iter()
            .any(|(_, provider)| provider.settings.should_enable_jwt_validation())
    }

    /// Check if a provider's client is configured
    #[must_use]
    pub fn get_client_configured(&self, provider: &str) -> bool {
        self.providers
            .get(provider)
            .is_some_and(RuntimeProvider::is_configured)
    }

    /// Get the authorization URL for a provider (optimized for performance)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The specified provider is not configured
    /// - The client ID is not configured for the provider
    /// - The authorization URL is malformed
    pub fn get_auth_url(&self, provider: &str, state: &str) -> Result<String, String> {
        let runtime_provider = self
            .providers
            .get(provider)
            .ok_or("Provider not configured")?;

        // Use pre-encoded client ID to avoid re-encoding on every request
        let encoded_client_id = runtime_provider
            .encoded_client_id
            .as_ref()
            .ok_or("Client ID not configured for provider")?;

        // Use cached encoded redirect URI from config for better performance
        let encoded_redirect_uri = &self.encoded_redirect_uri;

        // Use pre-encoded scopes from cached value
        let encoded_scopes = &runtime_provider.encoded_scopes;

        // Determine if auth URL already has query parameters
        let has_query_params = runtime_provider.auth_url.contains('?');
        let first_separator = if has_query_params { "&" } else { "?" };

        // Calculate total capacity needed to avoid reallocations
        let base_capacity = runtime_provider.auth_url.len()
            + first_separator.len()
            + "client_id=".len()
            + encoded_client_id.len()
            + "&response_type=code".len()
            + "&redirect_uri=".len()
            + encoded_redirect_uri.len()
            + "&state=".len()
            + state.len()
            + "&scope=".len()
            + encoded_scopes.len();

        // Add capacity for extra parameters
        let extra_params_capacity =
            runtime_provider
                .settings
                .extra_auth_params
                .as_ref()
                .map_or(0, |params| {
                    params.iter().fold(0, |acc, (k, v)| {
                        acc + "&".len() + k.len() + "=".len() + urlencoding::encode(v).len()
                    })
                });

        // Pre-allocate with the calculated capacity to avoid reallocations
        let mut url = String::with_capacity(base_capacity + extra_params_capacity);

        // Build URL efficiently with single pass - no intermediate allocations
        url.push_str(&runtime_provider.auth_url);
        url.push_str(first_separator);
        url.push_str("client_id=");
        url.push_str(encoded_client_id);
        url.push_str("&response_type=code");
        url.push_str("&redirect_uri=");
        url.push_str(encoded_redirect_uri);
        url.push_str("&state=");
        url.push_str(state);
        url.push_str("&scope=");
        url.push_str(encoded_scopes);

        // Add provider-specific extra parameters efficiently
        if let Some(ref extra_params) = runtime_provider.settings.extra_auth_params {
            for (key, value) in extra_params {
                url.push('&');
                url.push_str(key);
                url.push('=');
                url.push_str(&urlencoding::encode(value));
            }
        }

        info!(
            "🔍 Built {} OAuth URL with scopes: {} and extra params: {:?}",
            provider,
            // Decode for logging purposes only
            urlencoding::decode(encoded_scopes).unwrap_or_default(),
            runtime_provider.settings.extra_auth_params
        );

        Ok(url)
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
    pub async fn exchange_code_for_tokens(
        &self,
        provider: &str,
        code: &str,
    ) -> TokenExchangeResult {
        let runtime_provider = self
            .providers
            .get(provider)
            .ok_or("Provider not configured")?;

        // Prepare token exchange parameters
        let params = self.prepare_token_exchange_params(provider, code, runtime_provider)?;

        // Execute token exchange request
        let response_text = self
            .execute_token_exchange(provider, runtime_provider, &params)
            .await?;

        // Parse and process the token response, including JWT validation
        self.process_token_response(provider, &response_text, runtime_provider)
            .await
    }

    /// Prepare parameters for token exchange request
    fn prepare_token_exchange_params(
        &self,
        _provider: &str,
        code: &str,
        runtime_provider: &RuntimeProvider,
    ) -> Result<HashMap<String, String>, String> {
        // Pre-allocate redirect URI string to avoid format! allocation
        let mut redirect_uri = String::with_capacity(self.redirect_base_url.len() + 20);
        redirect_uri.push_str(&self.redirect_base_url);
        redirect_uri.push_str("/auth/oauth2/callback");

        let mut params = HashMap::new();

        // Basic OAuth parameters
        params.insert("grant_type".to_string(), "authorization_code".to_string());
        params.insert("code".to_string(), code.to_string());
        params.insert("redirect_uri".to_string(), redirect_uri);

        // Client credentials
        let client_id = runtime_provider
            .settings
            .get_client_id()
            .ok_or("Client ID not configured for provider")?;

        params.insert("client_id".to_string(), client_id);

        // Handle client secret or JWT signing
        if let Some(ref secret) = runtime_provider.client_secret {
            // Regular OAuth with client secret
            params.insert("client_secret".to_string(), secret.clone());
        } else if let Some(ref jwt_config) = runtime_provider.settings.jwt_signing {
            // JWT signing (Apple)
            let client_id = runtime_provider
                .settings
                .get_client_id()
                .ok_or("Client ID not configured for provider")?;
            let client_secret =
                crate::utils::apple::generate_jwt_client_secret(jwt_config, &client_id)?;
            params.insert("client_secret".to_string(), client_secret);
        } else {
            return Err("No client secret or JWT signing configuration for provider".to_string());
        }

        Ok(params)
    }

    /// Execute the token exchange HTTP request
    async fn execute_token_exchange(
        &self,
        provider: &str,
        runtime_provider: &RuntimeProvider,
        params: &HashMap<String, String>,
    ) -> Result<String, String> {
        info!("🔄 Exchanging authorization code for tokens with {provider}");

        let response = CLIENT
            .post(&runtime_provider.token_url)
            .form(params)
            .send()
            .await
            .map_err(|e| format!("Failed to send token exchange request: {e}"))?;

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

        response
            .text()
            .await
            .map_err(|e| format!("Failed to read response text: {e}"))
    }

    /// Process the token response and extract relevant information
    async fn process_token_response(
        &self,
        provider: &str,
        response_text: &str,
        runtime_provider: &RuntimeProvider,
    ) -> TokenExchangeResult {
        // Log the raw token response for debugging
        if provider == "apple" {
            info!("=== Raw Apple Token Response ===");
            info!("Response text: {response_text}");
            info!("=== End Raw Apple Token Response ===");
        } else {
            debug!("Raw {provider} token response: {response_text}");
        }

        let token_response: TokenResponse = serde_json::from_str(response_text)
            .map_err(|e| format!("Failed to parse token response: {e}"))?;

        // Calculate token expiration
        let expires_at = token_response.expires_in.map_or_else(
            || {
                // Default to 1 hour if no expiration provided
                Utc::now() + chrono::Duration::hours(1)
            },
            |expires_in| {
                Utc::now() + chrono::Duration::seconds(i64::try_from(expires_in).unwrap_or(3600))
            },
        );

        // Perform JWT validation if enabled and ID token is present
        if let Some(ref id_token) = token_response.id_token {
            if runtime_provider.settings.should_enable_jwt_validation() {
                info!("🔐 Performing JWT validation for provider '{provider}'");
                if let Err(e) = self
                    .validate_jwt_token(provider, id_token, runtime_provider)
                    .await
                {
                    warn!("❌ JWT validation failed for provider '{provider}': {e}");
                    // Continue for now - in the future this could be configurable
                    // return Err(format!("JWT validation failed: {}", e));
                }
            } else {
                debug!("⏭️  JWT validation disabled for provider '{provider}'");
            }
        }

        // Log detailed information about what we extracted
        let refresh_status = token_response
            .refresh_token
            .as_ref()
            .map_or("No", |_| "Yes");
        let id_status = token_response.id_token.as_ref().map_or("No", |_| "Yes");
        let expires_in = token_response
            .expires_in
            .map(|v| i64::try_from(v).unwrap_or(3600));

        info!("🔍 Token exchange summary for {}: refresh_token={}, id_token={}, token_type={}, expires_in={:?}",
            provider, refresh_status, id_status, token_response.token_type, expires_in);

        Ok((
            token_response.id_token,
            token_response.refresh_token,
            expires_at,
            token_response.user,
        ))
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
        self.providers
            .keys()
            .map(std::string::String::as_str)
            .collect()
    }

    /// Get provider display name
    #[must_use]
    pub fn get_provider_display_name(&self, provider: &str) -> Option<&str> {
        self.providers
            .get(provider)
            .and_then(|p| p.settings.display_name.as_deref())
    }

    /// Validate JWT ID token using JWKS discovery and cryptographic verification
    async fn validate_jwt_token(
        &self,
        provider: &str,
        id_token: &str,
        runtime_provider: &RuntimeProvider,
    ) -> Result<(), crate::oauth::jwt_validation::JwtValidationError> {
        let jwt_config = runtime_provider.settings.get_jwt_validation_config();

        // Get the JWT validator
        let validator = self.get_jwt_validator().await;

        // If discovery URL is available, fetch discovery document for issuer/jwks_uri
        let discovery_doc = if let Some(ref discovery_url) = runtime_provider.settings.discovery_url
        {
            match crate::oauth::fetch_discovery_document(discovery_url).await {
                Ok(doc) => {
                    debug!("✅ Discovery document fetched for provider '{provider}'");
                    // Parse the JSON into the proper type
                    match serde_json::from_value::<
                        crate::oauth::jwt_validation::OidcDiscoveryDocument,
                    >(doc)
                    {
                        Ok(parsed_doc) => Some(parsed_doc),
                        Err(e) => {
                            warn!("⚠️  Failed to parse discovery document for '{provider}': {e}");
                            None
                        }
                    }
                }
                Err(e) => {
                    warn!("⚠️  Failed to fetch discovery document for '{provider}': {e}");
                    None
                }
            }
        } else {
            None
        };

        // Perform JWT validation using the validator
        validator
            .validate_id_token(id_token, provider, &jwt_config, discovery_doc.as_ref())
            .await
    }
}

// ============================================================================
// Token Management Functions
// ============================================================================

/// Check and refresh OAuth tokens if they are close to expiry
///
/// # Errors
///
/// Returns an error HTTP response if:
/// - Session tokens are expired and no refresh token is available
/// - Token refresh operation fails
/// - Provider is not configured for refresh
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
    match refresh_tokens(refresh_token, oauth_config, provider).await {
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
pub async fn refresh_tokens(
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
        // Generate JWT client secret for Apple
        let client_id = runtime_provider
            .settings
            .get_client_id()
            .ok_or_else(|| format!("Client ID not configured for provider {provider}"))?;
        apple::generate_jwt_client_secret(jwt_config, &client_id)
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

    let new_expires_at =
        chrono::Utc::now() + chrono::Duration::seconds(i64::try_from(expires_in).unwrap_or(3600));

    Ok((new_id_token, new_refresh_token, new_expires_at))
}
