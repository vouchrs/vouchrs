//! OAuth authentication module
//!
//! This module provides OAuth functionality including service implementations,
//! provider management, and token processing for all OAuth providers.

pub mod config;
pub mod jwt_validation;
pub mod providers;
pub mod service;
pub mod tokens;

// Re-export main configuration and utility types
pub use config::{check_and_refresh_tokens, refresh_tokens, OAuthConfig, RuntimeProvider};

// Re-export service types
pub use service::{
    OAuthAuthenticationService, OAuthAuthenticationServiceImpl, OAuthError, OAuthFlowResult,
    OAuthResult,
};

// Re-export token processing functions
pub use tokens::{extract_email, process_id_token};

// Re-export JWT validation types
pub use jwt_validation::{JwtValidationError, JwtValidator, OidcDiscoveryDocument};

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

// OAuth state parsing function moved to session::utils module to avoid circular dependency

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
