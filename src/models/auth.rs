//! Common authentication data types
//!
//! This module provides unified data structures and error types that can be used
//! across all authentication methods (OAuth, Passkey, etc.)

use crate::models::{VouchrsSession, VouchrsUserData};
use crate::oauth::service::OAuthError;
use crate::passkey::PasskeyError;
use std::fmt;

/// Common result type for all authentication methods
///
/// This structure provides a unified interface for authentication results
/// regardless of the authentication method used (OAuth, Passkey, etc.)
#[derive(Debug, Clone)]
pub struct AuthenticationResult {
    /// The session data containing tokens and authentication state
    pub session: VouchrsSession,
    /// The user data containing profile information and client context
    pub user_data: VouchrsUserData,
    /// Optional redirect URL after successful authentication
    pub redirect_url: Option<String>,
}

impl AuthenticationResult {
    /// Create a new authentication result
    #[must_use]
    pub fn new(
        session: VouchrsSession,
        user_data: VouchrsUserData,
        redirect_url: Option<String>,
    ) -> Self {
        Self {
            session,
            user_data,
            redirect_url,
        }
    }

    /// Create authentication result with default redirect
    #[must_use]
    pub fn with_default_redirect(session: VouchrsSession, user_data: VouchrsUserData) -> Self {
        Self {
            session,
            user_data,
            redirect_url: Some("/".to_string()),
        }
    }
}

/// Common error type for authentication operations
///
/// This enum unifies all possible authentication errors across different
/// authentication methods, making error handling consistent throughout
/// the application.
#[derive(Debug)]
pub enum AuthenticationError {
    /// OAuth-specific authentication errors
    OAuth(OAuthError),
    /// Passkey-specific authentication errors
    Passkey(PasskeyError),
    /// Session management errors
    Session(SessionError),
    /// Invalid request data or parameters
    InvalidRequest(String),
    /// Service not available or misconfigured
    ServiceUnavailable(String),
    /// Internal system errors
    InternalError(String),
}

impl fmt::Display for AuthenticationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthenticationError::OAuth(err) => write!(f, "OAuth error: {err}"),
            AuthenticationError::Passkey(err) => write!(f, "Passkey error: {err}"),
            AuthenticationError::Session(err) => write!(f, "Session error: {err}"),
            AuthenticationError::InvalidRequest(msg) => write!(f, "Invalid request: {msg}"),
            AuthenticationError::ServiceUnavailable(msg) => write!(f, "Service unavailable: {msg}"),
            AuthenticationError::InternalError(msg) => write!(f, "Internal error: {msg}"),
        }
    }
}

impl std::error::Error for AuthenticationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AuthenticationError::OAuth(err) => Some(err),
            AuthenticationError::Passkey(err) => Some(err),
            AuthenticationError::Session(err) => Some(err),
            _ => None,
        }
    }
}

// Implement conversions from specific error types
impl From<OAuthError> for AuthenticationError {
    fn from(err: OAuthError) -> Self {
        AuthenticationError::OAuth(err)
    }
}

impl From<PasskeyError> for AuthenticationError {
    fn from(err: PasskeyError) -> Self {
        AuthenticationError::Passkey(err)
    }
}

impl From<SessionError> for AuthenticationError {
    fn from(err: SessionError) -> Self {
        AuthenticationError::Session(err)
    }
}

/// Session management errors
#[derive(Debug)]
pub enum SessionError {
    /// Session creation failed
    CreationFailed(String),
    /// Session validation failed
    ValidationFailed(String),
    /// Session expired
    Expired(String),
    /// Session encryption/decryption failed
    CryptographyFailed(String),
    /// Client context validation failed (session hijacking prevention)
    ClientContextFailed(String),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::CreationFailed(msg) => write!(f, "Session creation failed: {msg}"),
            SessionError::ValidationFailed(msg) => write!(f, "Session validation failed: {msg}"),
            SessionError::Expired(msg) => write!(f, "Session expired: {msg}"),
            SessionError::CryptographyFailed(msg) => {
                write!(f, "Session cryptography failed: {msg}")
            }
            SessionError::ClientContextFailed(msg) => {
                write!(f, "Client context validation failed: {msg}")
            }
        }
    }
}

impl std::error::Error for SessionError {}

/// Authentication request types for different authentication methods
#[derive(Debug, Clone)]
pub enum AuthenticationRequest {
    /// OAuth callback processing request
    OAuth {
        provider: String,
        authorization_code: String,
        oauth_state: crate::oauth::OAuthState,
        apple_user_info: Option<crate::utils::apple::AppleUserInfo>,
    },
    /// OAuth flow initiation request
    OAuthFlow {
        provider: String,
        redirect_uri: String,
    },
    /// OAuth token refresh request
    OAuthRefresh {
        provider: String,
        refresh_token: String,
    },
    /// Passkey registration request
    PasskeyRegistration {
        credential_response: webauthn_rs::prelude::RegisterPublicKeyCredential,
        registration_state: webauthn_rs::prelude::PasskeyRegistration,
        user_data: crate::passkey::PasskeyUserData,
    },
    /// Passkey authentication request
    PasskeyAuthentication {
        credential_response: webauthn_rs::prelude::PublicKeyCredential,
        authentication_state: webauthn_rs::prelude::PasskeyAuthentication,
        user_data: Option<crate::passkey::PasskeyUserData>,
    },
}

/// Authentication response types for different operations
#[derive(Debug, Clone)]
pub enum AuthenticationResponse {
    /// Standard authentication result with session and user data
    Session(AuthenticationResult),
    /// OAuth flow initiation result with authorization URL
    OAuthFlow {
        authorization_url: String,
        oauth_state: crate::oauth::OAuthState,
    },
    /// Passkey registration start result
    PasskeyRegistrationStart {
        options: webauthn_rs::prelude::CreationChallengeResponse,
        state: webauthn_rs::prelude::PasskeyRegistration,
        user_handle: String,
    },
    /// Passkey authentication start result
    PasskeyAuthenticationStart {
        options: webauthn_rs::prelude::RequestChallengeResponse,
        state: webauthn_rs::prelude::PasskeyAuthentication,
    },
}
