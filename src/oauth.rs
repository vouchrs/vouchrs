// Config-driven OAuth implementation using provider configurations from settings
// Supports dynamic discovery endpoints and customizable provider configurations

// Standard library imports
use std::collections::HashMap;
use std::env;

// Third-party imports
use actix_web::HttpResponse;
use chrono::Utc;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// Local imports
use crate::models::VouchrsSession;
use crate::settings::{ProviderSettings, VouchrsSettings};
use crate::utils::apple;
use crate::utils::crypto::decrypt_data;
#[cfg(test)]
use crate::utils::crypto::encrypt_data;


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

/// OAuth callback structure for handling responses from OAuth providers
#[derive(Deserialize, Debug)]
pub struct OAuthCallback {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub user: Option<serde_json::Value>, // Apple sends user info in form POST on first login
}

/// OAuth state structure for CSRF protection and flow tracking
#[derive(Serialize, Deserialize, Debug)]
pub struct OAuthState {
    pub state: String,
    pub provider: String,
    pub redirect_url: Option<String>,
}

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

/// Runtime provider configuration with resolved endpoints
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

        Ok(Self {
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
        info!("🔧 Initializing OAuth providers from configuration...");

        for provider_settings in &settings.providers {
            if !provider_settings.enabled {
                info!("⏭️  Provider {} is disabled, skipping", provider_settings.name);
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
    pub fn get_auth_url(&self, provider: &str, state: &str) -> Result<String, String> {
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

        info!(
            "🔍 Built {} OAuth URL with scopes: {} and extra params: {:?}",
            provider, scopes, runtime_provider.settings.extra_auth_params
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
    pub async fn exchange_code_for_tokens(
        &self,
        provider: &str,
        code: &str,
    ) -> TokenExchangeResult {
        let runtime_provider = self
            .providers
            .get(provider)
            .ok_or_else(|| format!("Provider {provider} not configured"))?;

        // Prepare token exchange parameters
        let params = self.prepare_token_exchange_params(provider, code, runtime_provider)?;

        // Execute token exchange request
        let response_text = self.execute_token_exchange(provider, runtime_provider, &params).await?;

        // Parse and process the token response
        Self::process_token_response(provider, &response_text)
    }

    /// Prepare parameters for token exchange request
    fn prepare_token_exchange_params(
        &self,
        provider: &str,
        code: &str,
        runtime_provider: &RuntimeProvider,
    ) -> Result<HashMap<String, String>, String> {
        let redirect_uri = format!("{}/oauth2/callback", self.redirect_base_url);
        let mut params = HashMap::new();
        
        // Basic OAuth parameters
        params.insert("grant_type".to_string(), "authorization_code".to_string());
        params.insert("code".to_string(), code.to_string());
        params.insert("redirect_uri".to_string(), redirect_uri);

        // Client credentials
        let client_id = runtime_provider
            .settings
            .get_client_id()
            .ok_or_else(|| format!("Client ID not configured for provider {provider}"))?;

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
                .ok_or_else(|| format!("Client ID not configured for provider {provider}"))?;
            let client_secret = crate::utils::apple::generate_jwt_client_secret(jwt_config, &client_id)?;
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
        
        let response = self
            .http_client
            .post(&runtime_provider.token_url)
            .form(params)
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

        response
            .text()
            .await
            .map_err(|e| format!("Failed to read response text: {e}"))
    }

    /// Process the token response and extract relevant information
    fn process_token_response(
        provider: &str,
        response_text: &str,
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
        let expires_at = token_response.expires_in.map_or_else(|| {
            // Default to 1 hour if no expiration provided
            Utc::now() + chrono::Duration::hours(1)
        }, |expires_in| {
            Utc::now() + chrono::Duration::seconds(i64::try_from(expires_in).unwrap_or(3600))
        });

        // Log detailed information about what we extracted
        let refresh_status = token_response.refresh_token.as_ref().map_or("No", |_| "Yes");
        let id_status = token_response.id_token.as_ref().map_or("No", |_| "Yes");
        let expires_in = token_response.expires_in.map(|v| i64::try_from(v).unwrap_or(3600));
        
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



// ============================================================================
// Token Management Functions
// ============================================================================

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

    let new_expires_at = chrono::Utc::now() + chrono::Duration::seconds(i64::try_from(expires_in).unwrap_or(3600));

    Ok((new_id_token, new_refresh_token, new_expires_at))
}

// ============================================================================
// Utility Functions
// ============================================================================

// ============================================================================
// OAuth State Management
// ============================================================================

/// Parse OAuth state from received state parameter and retrieve stored state from cookie
/// This eliminates provider-specific branching logic by using the stored OAuth state
/// 
/// # Errors
/// 
/// Returns an error if:
/// - The received state does not match the stored CSRF token
/// - No stored state is found and encrypted state decryption fails
/// - The encrypted state format is invalid
pub fn get_state_from_callback(
    received_state: &str,
    session_manager: &crate::session::SessionManager,
    req: &actix_web::HttpRequest,
) -> Result<crate::oauth::OAuthState, String> {
    debug!("Received OAuth state parameter: length = {} characters", received_state.len());

    // First, try to get the stored OAuth state from temporary cookie (legacy compatibility)
    match session_manager.get_temporary_state_from_request(req) {
        Ok(Some(stored_state)) => {
            // For legacy cookie-based state, verify the received state matches the stored CSRF token
            if stored_state.state == received_state {
                debug!(
                    "OAuth state verified: stored state matches received state for provider {}",
                    stored_state.provider
                );
                Ok(stored_state)
            } else {
                Err(
                    "OAuth state mismatch: received state does not match stored CSRF token"
                        .to_string(),
                )
            }
        }
        Ok(None) => {
            // 🔒 SECURITY: Try to decrypt the received state parameter
            // This prevents tampering with provider name or redirect URL
            match decrypt_data::<crate::oauth::OAuthState>(received_state, session_manager.encryption_key()) {
                Ok(decrypted_state) => {
                    debug!(
                        "Successfully decrypted OAuth state for provider: {}",
                        decrypted_state.provider
                    );
                    Ok(decrypted_state)
                }
                Err(e) => {
                    debug!("Failed to decrypt OAuth state: {e}");
                    Err("Invalid OAuth state: cannot decrypt state parameter".to_string())
                }
            }
        }
        Err(e) => {
            debug!("Failed to retrieve stored OAuth state: {e}");
            // Try decrypting the state parameter directly
            match decrypt_data::<crate::oauth::OAuthState>(received_state, session_manager.encryption_key()) {
                Ok(decrypted_state) => {
                    debug!(
                        "Successfully decrypted OAuth state for provider: {}",
                        decrypted_state.provider
                    );
                    Ok(decrypted_state)
                }
                Err(decrypt_error) => {
                    debug!("Failed to decrypt OAuth state: {decrypt_error}");
                    Err("Invalid OAuth state: cannot decrypt state parameter".to_string())
                }
            }
        }
    }
}



// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;



    #[test]
    fn test_encrypted_state_security_fix() {
        use crate::utils::test_helpers::create_test_session_manager;
        
        // Create a session manager for encryption/decryption
        let session_manager = create_test_session_manager();
        
        // Create an OAuth state
        let original_state = OAuthState {
            state: "csrf_token_123".to_string(),
            provider: "google".to_string(),
            redirect_url: Some("/dashboard".to_string()),
        };
        
        // Encrypt the state (this is what we now do in auth.rs)
        let encrypted_state = encrypt_data(&original_state, session_manager.encryption_key()).unwrap();
        
        // Verify that the encrypted state doesn't contain plain text provider info
        assert!(!encrypted_state.contains("google"));
        assert!(!encrypted_state.contains("dashboard"));
        assert!(!encrypted_state.contains("csrf_token_123"));
        
        // Verify that we can decrypt it back correctly
        let decrypted_state: OAuthState = decrypt_data(&encrypted_state, session_manager.encryption_key()).unwrap();
        assert_eq!(decrypted_state.state, original_state.state);
        assert_eq!(decrypted_state.provider, original_state.provider);
        assert_eq!(decrypted_state.redirect_url, original_state.redirect_url);
    }

    #[test]
    fn test_tampered_encrypted_state_fails() {
        use crate::utils::test_helpers::create_test_session_manager;
        
        let session_manager = create_test_session_manager();
        
        let original_state = OAuthState {
            state: "csrf_token_123".to_string(),
            provider: "google".to_string(),
            redirect_url: Some("/dashboard".to_string()),
        };
        
        let encrypted_state = encrypt_data(&original_state, session_manager.encryption_key()).unwrap();
        
        // Tamper with the encrypted state by changing one character
        let mut chars: Vec<char> = encrypted_state.chars().collect();
        if let Some(last_char) = chars.last_mut() {
            *last_char = if *last_char == 'A' { 'B' } else { 'A' };
        }
        let tampered_state: String = chars.into_iter().collect();
        
        // Attempting to decrypt tampered state should fail
        let result = decrypt_data::<OAuthState>(&tampered_state, session_manager.encryption_key());
        assert!(result.is_err());
    }


}
