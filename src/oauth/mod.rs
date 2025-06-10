//! OAuth authentication module
//!
//! This module provides OAuth functionality including service implementations,
//! provider management, and token processing for all OAuth providers.

pub mod config;
pub mod jwt_validation;
pub mod providers;
pub mod service;
pub mod token_processor;

// Re-export main configuration and utility types
pub use config::{check_and_refresh_tokens, refresh_tokens, OAuthConfig, RuntimeProvider};

// Re-export service types
pub use service::{
    OAuthAuthenticationService, OAuthAuthenticationServiceImpl, OAuthError, OAuthFlowResult,
    OAuthSessionResult, OAuthTokenRefreshResult,
};

// Re-export JWT validation types
pub use jwt_validation::{JwtValidationError, JwtValidator, OidcDiscoveryDocument};

// Re-export token processing types
pub use token_processor::{IdTokenProcessor, TokenProcessingResult};

use crate::utils::crypto::decrypt_data;
use serde::{Deserialize, Serialize};

// Essential OAuth structures that are used throughout the codebase
/// OAuth callback structure for handling responses from OAuth providers
#[derive(Deserialize, Debug)]
pub struct OAuthCallback {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub user: Option<serde_json::Value>, // Apple sends user info in form POST on first login
}

/// OAuth state structure for CSRF protection and flow tracking
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OAuthState {
    pub state: String,
    pub provider: String,
    pub redirect_url: Option<String>,
}

// Essential OAuth functions that are used throughout the codebase

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
) -> Result<OAuthState, String> {
    log::debug!(
        "Received OAuth state parameter: length = {} characters",
        received_state.len()
    );

    // First, try to get the stored OAuth state from temporary cookie
    match session_manager.get_temporary_state_from_request(req) {
        Ok(Some(stored_state)) => {
            // For cookie-based state, verify the received state matches the stored CSRF token
            if stored_state.state == received_state {
                log::debug!(
                    "OAuth state verified: stored state matches received state for provider {}",
                    stored_state.provider
                );
                // Convert stored OAuth state to oauth::OAuthState
                Ok(OAuthState {
                    state: stored_state.state,
                    provider: stored_state.provider,
                    redirect_url: stored_state.redirect_url,
                })
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
            match decrypt_data::<OAuthState>(received_state, session_manager.encryption_key()) {
                Ok(decrypted_state) => {
                    log::debug!(
                        "Successfully decrypted OAuth state for provider: {}",
                        decrypted_state.provider
                    );
                    Ok(decrypted_state)
                }
                Err(e) => {
                    log::debug!("Failed to decrypt OAuth state: {e}");
                    Err("Invalid OAuth state: cannot decrypt state parameter".to_string())
                }
            }
        }
        Err(e) => {
            log::debug!("Failed to get stored OAuth state: {e}");
            Err("Invalid OAuth state: no stored state found".to_string())
        }
    }
}

/// Fetch discovery document from the given URL
///
/// # Errors
///
/// Returns an error if:
/// - Network request fails
/// - Response is not valid JSON
/// - Response doesn't contain required fields
pub async fn fetch_discovery_document(discovery_url: &str) -> Result<serde_json::Value, String> {
    log::debug!("Fetching discovery document from: {discovery_url}");

    let client = reqwest::Client::new();
    let response = client
        .get(discovery_url)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch discovery document: {e}"))?;

    if !response.status().is_success() {
        return Err(format!(
            "Discovery document request failed with status: {}",
            response.status()
        ));
    }

    let document: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse discovery document JSON: {e}"))?;

    log::debug!("Successfully fetched discovery document");
    Ok(document)
}

/// Fetch JWKS (JSON Web Key Set) from the given URL
///
/// # Errors
///
/// Returns an error if:
/// - Network request fails
/// - Response is not valid JSON
/// - Response doesn't contain valid JWKS format
pub async fn fetch_jwks(jwks_uri: &str) -> Result<serde_json::Value, String> {
    log::debug!("Fetching JWKS from: {jwks_uri}");

    let client = reqwest::Client::new();
    let response = client
        .get(jwks_uri)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch JWKS: {e}"))?;

    if !response.status().is_success() {
        return Err(format!(
            "JWKS request failed with status: {}",
            response.status()
        ));
    }

    let jwks: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse JWKS JSON: {e}"))?;

    log::debug!("Successfully fetched JWKS");
    Ok(jwks)
}
