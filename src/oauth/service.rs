//! OAuth authentication service implementations
//!
//! This module provides the OAuth authentication service that handles OAuth flows,
//! token processing, and session creation for all OAuth providers.

use crate::models::{VouchrsSession, VouchrsUserData};
use crate::oauth::token_processor::IdTokenProcessor;
use crate::oauth::{OAuthConfig, OAuthState};
use crate::settings::VouchrsSettings;
use crate::utils::apple::AppleUserInfo;
use anyhow::Result;
use async_trait::async_trait;
use chrono;
use std::fmt;

/// OAuth authentication errors
#[derive(Debug)]
pub enum OAuthError {
    Provider(String),
    TokenExchange(String),
    IdToken(String),
    SessionCreation(String),
    Configuration(String),
}

impl fmt::Display for OAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OAuthError::Provider(msg) => write!(f, "OAuth provider error: {msg}"),
            OAuthError::TokenExchange(msg) => write!(f, "Token exchange failed: {msg}"),
            OAuthError::IdToken(msg) => write!(f, "ID token processing failed: {msg}"),
            OAuthError::SessionCreation(msg) => write!(f, "Session creation failed: {msg}"),
            OAuthError::Configuration(msg) => write!(f, "Configuration error: {msg}"),
        }
    }
}

impl std::error::Error for OAuthError {}

/// Result of OAuth callback processing
#[derive(Debug, Clone)]
pub struct OAuthSessionResult {
    pub session: VouchrsSession,
    pub user_data: VouchrsUserData,
    pub redirect_url: Option<String>,
}

impl OAuthSessionResult {
    /// Convert to the common `AuthenticationResult` type
    #[must_use]
    pub fn into_auth_result(self) -> crate::models::auth::AuthenticationResult {
        crate::models::auth::AuthenticationResult::new(
            self.session,
            self.user_data,
            self.redirect_url,
        )
    }

    /// Create from the common `AuthenticationResult` type
    #[must_use]
    pub fn from_auth_result(auth_result: crate::models::auth::AuthenticationResult) -> Self {
        Self {
            session: auth_result.session,
            user_data: auth_result.user_data,
            redirect_url: auth_result.redirect_url,
        }
    }
}

/// Result of OAuth flow initiation
#[derive(Debug, Clone)]
pub struct OAuthFlowResult {
    pub authorization_url: String,
    pub oauth_state: OAuthState,
}

/// Result of OAuth token refresh
#[derive(Debug, Clone)]
pub struct OAuthTokenRefreshResult {
    pub session: VouchrsSession,
    pub user_data: VouchrsUserData,
}

/// OAuth authentication service trait
#[async_trait]
pub trait OAuthAuthenticationService {
    /// Process OAuth callback and create session data
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Provider is not configured
    /// - Authorization code exchange fails
    /// - ID token processing fails
    /// - Session creation fails
    async fn process_oauth_callback(
        &self,
        provider: &str,
        authorization_code: &str,
        oauth_state: &OAuthState,
        apple_user_info: Option<AppleUserInfo>,
    ) -> Result<OAuthSessionResult, OAuthError>;

    /// Initiate OAuth flow
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Provider is not configured
    /// - OAuth configuration is invalid
    /// - State generation fails
    async fn initiate_oauth_flow(
        &self,
        provider: &str,
        redirect_uri: &str,
    ) -> Result<OAuthFlowResult, OAuthError>;

    /// Refresh OAuth tokens
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Provider is not configured
    /// - Refresh token is invalid
    /// - Token refresh request fails
    async fn refresh_oauth_tokens(
        &self,
        provider: &str,
        refresh_token: &str,
    ) -> Result<OAuthTokenRefreshResult, OAuthError>;
}

/// OAuth authentication service implementation
pub struct OAuthAuthenticationServiceImpl {
    settings: VouchrsSettings,
}

impl OAuthAuthenticationServiceImpl {
    /// Create a new OAuth authentication service
    #[must_use]
    pub fn new(settings: VouchrsSettings) -> Self {
        Self { settings }
    }

    /// Get or create OAuth config (lazy initialization)
    async fn get_oauth_config(&self) -> Result<OAuthConfig, OAuthError> {
        let mut oauth_config = OAuthConfig::new();
        oauth_config
            .initialize_from_settings(&self.settings)
            .await
            .map_err(|e| {
                OAuthError::Configuration(format!("Failed to initialize OAuth config: {e}"))
            })?;
        Ok(oauth_config)
    }
}

#[async_trait]
impl OAuthAuthenticationService for OAuthAuthenticationServiceImpl {
    async fn process_oauth_callback(
        &self,
        provider: &str,
        authorization_code: &str,
        oauth_state: &OAuthState,
        apple_user_info: Option<AppleUserInfo>,
    ) -> Result<OAuthSessionResult, OAuthError> {
        self.process_oauth_callback_async(
            provider,
            authorization_code,
            oauth_state,
            apple_user_info,
        ).await
    }

    async fn initiate_oauth_flow(
        &self,
        provider: &str,
        redirect_uri: &str,
    ) -> Result<OAuthFlowResult, OAuthError> {
        let oauth_config = self.get_oauth_config().await?;

        // Use the OAuth config to generate authorization URL
        let state = format!("{}_{}", provider, chrono::Utc::now().timestamp());
        let auth_url = oauth_config
            .get_auth_url(provider, &state)
            .map_err(|e| OAuthError::Configuration(format!("Failed to get auth URL: {e}")))?;

        let oauth_state = OAuthState {
            state,
            provider: provider.to_string(),
            redirect_url: Some(redirect_uri.to_string()),
        };

        Ok(OAuthFlowResult {
            authorization_url: auth_url,
            oauth_state,
        })
    }

    async fn refresh_oauth_tokens(
        &self,
        _provider: &str,
        _refresh_token: &str,
    ) -> Result<OAuthTokenRefreshResult, OAuthError> {
        // TODO: Implement token refresh using the OAuth config
        // For now, return an error until this is implemented
        Err(OAuthError::Configuration(
            "Token refresh not yet implemented in the new service".to_string(),
        ))
    }
}

impl OAuthAuthenticationServiceImpl {
    /// Internal async implementation of OAuth callback processing
    async fn process_oauth_callback_async(
        &self,
        provider: &str,
        authorization_code: &str,
        oauth_state: &OAuthState,
        apple_user_info: Option<AppleUserInfo>,
    ) -> Result<OAuthSessionResult, OAuthError> {
        // Get OAuth config with lazy initialization
        let oauth_config = self.get_oauth_config().await?;

        // Use OAuth config to exchange code for tokens
        let (id_token, refresh_token, expires_at, apple_user_info_fallback) = oauth_config
            .exchange_code_for_tokens(provider, authorization_code)
            .await
            .map_err(|e| OAuthError::TokenExchange(format!("Token exchange failed: {e}")))?;

        // Use the apple_user_info parameter if available, otherwise use fallback from token exchange
        let final_apple_user_info = apple_user_info.or(apple_user_info_fallback);

        // Extract client info (simplified for now)
        let client_ip = None; // Would need request context
        let user_agent_info = None; // Would need request context

        // Process ID token and create session using IdTokenProcessor
        let token_result = IdTokenProcessor::process_id_token(
            provider,
            id_token.as_deref(),
            refresh_token.clone(),
            expires_at,
            final_apple_user_info.as_ref(),
            client_ip,
            user_agent_info.as_ref(),
        )
        .map_err(|e| OAuthError::IdToken(format!("ID token processing failed: {e}")))?;

        Ok(OAuthSessionResult {
            session: token_result.session,
            user_data: token_result.user_data,
            redirect_url: oauth_state.redirect_url.clone(),
        })
    }
}
