//! Unified authentication traits
//!
//! This module provides common authentication traits that all authentication
//! services implement, enabling consistent interfaces and pluggable authentication
//! methods.

use crate::models::auth::{AuthenticationError, AuthenticationRequest, AuthenticationResponse};

/// Base authentication service trait
///
/// This trait provides a unified interface for all authentication services,
/// regardless of the authentication method (OAuth, Passkey, etc.).
///
/// All authentication services should implement this trait to ensure
/// consistent behavior and enable dependency injection.
pub trait AuthenticationService {
    /// Process an authentication request
    ///
    /// # Arguments
    /// * `request` - The authentication request to process
    ///
    /// # Returns
    /// * `Ok(AuthenticationResponse)` - Successful authentication response
    /// * `Err(AuthenticationError)` - Authentication failure
    ///
    /// # Errors
    /// Returns an error if:
    /// - The authentication request is invalid
    /// - The authentication method fails
    /// - Session creation fails
    /// - The service is not available
    fn authenticate(
        &self,
        request: AuthenticationRequest,
    ) -> Result<AuthenticationResponse, AuthenticationError>;

    /// Check if the service is available and configured
    ///
    /// # Returns
    /// `true` if the service is available and properly configured, `false` otherwise
    fn is_available(&self) -> bool;

    /// Get the service name for logging and identification
    ///
    /// # Returns
    /// A string identifying the authentication service (e.g., "oauth", "passkey")
    fn service_name(&self) -> &'static str;
}

/// OAuth-specific authentication service trait
///
/// This trait extends the base authentication service with OAuth-specific
/// operations. OAuth services should implement both this trait and the
/// base `AuthenticationService` trait.
pub trait OAuthAuthenticationService: AuthenticationService {
    /// Process OAuth callback and create session data
    ///
    /// # Arguments
    /// * `provider` - The OAuth provider name (e.g., "google", "apple")
    /// * `authorization_code` - The authorization code from the OAuth callback
    /// * `oauth_state` - The OAuth state parameter for security validation
    /// * `apple_user_info` - Optional Apple user info for Apple OAuth
    ///
    /// # Returns
    /// * `Ok(AuthenticationResponse::Session)` - Successful authentication with session data
    /// * `Err(AuthenticationError)` - Authentication failure
    ///
    /// # Errors
    /// Returns an error if:
    /// - Provider is not configured
    /// - Authorization code exchange fails
    /// - ID token processing fails
    /// - Session creation fails
    fn process_oauth_callback(
        &self,
        provider: &str,
        authorization_code: &str,
        oauth_state: &crate::oauth::OAuthState,
        apple_user_info: Option<crate::utils::apple::AppleUserInfo>,
    ) -> Result<crate::models::auth::AuthenticationResult, crate::oauth::service::OAuthError>;

    /// Initiate OAuth flow
    ///
    /// # Arguments
    /// * `provider` - The OAuth provider name
    /// * `redirect_uri` - The redirect URI for the OAuth callback
    ///
    /// # Returns
    /// * `Ok(AuthenticationResponse::OAuthFlow)` - OAuth flow initiation data
    /// * `Err(AuthenticationError)` - Flow initiation failure
    ///
    /// # Errors
    /// Returns an error if:
    /// - Provider is not configured
    /// - OAuth configuration is invalid
    /// - State generation fails
    fn initiate_oauth_flow(
        &self,
        provider: &str,
        redirect_uri: &str,
    ) -> Result<crate::oauth::service::OAuthFlowResult, crate::oauth::service::OAuthError>;

    /// Refresh OAuth tokens
    ///
    /// # Arguments
    /// * `provider` - The OAuth provider name
    /// * `refresh_token` - The refresh token to use
    ///
    /// # Returns
    /// * `Ok(AuthenticationResponse::Session)` - Updated session with new tokens
    /// * `Err(AuthenticationError)` - Token refresh failure
    ///
    /// # Errors
    /// Returns an error if:
    /// - Provider is not configured
    /// - Refresh token is invalid
    /// - Token refresh request fails
    fn refresh_oauth_tokens(
        &self,
        provider: &str,
        refresh_token: &str,
    ) -> Result<crate::oauth::service::OAuthTokenRefreshResult, crate::oauth::service::OAuthError>;
}

/// Passkey-specific authentication service trait
///
/// This trait extends the base authentication service with Passkey-specific
/// operations. Passkey services should implement both this trait and the
/// base `AuthenticationService` trait.
pub trait PasskeyAuthenticationService: AuthenticationService {
    /// Complete passkey registration
    ///
    /// # Arguments
    /// * `credential_response` - The credential response from the client
    /// * `registration_state` - The registration state from the server
    /// * `user_data` - The user data for the registration
    ///
    /// # Returns
    /// * `Ok(AuthenticationResponse::Session)` - Successful registration with session data
    /// * `Err(AuthenticationError)` - Registration failure
    ///
    /// # Errors
    /// Returns an error if:
    /// - The service is not available (passkeys disabled)
    /// - Registration data is invalid
    /// - `WebAuthn` registration fails
    /// - Session creation fails
    fn complete_registration(
        &self,
        credential_response: &webauthn_rs::prelude::RegisterPublicKeyCredential,
        registration_state: &webauthn_rs::prelude::PasskeyRegistration,
        user_data: &crate::passkey::PasskeyUserData,
    ) -> Result<crate::models::auth::AuthenticationResult, crate::passkey::PasskeyError>;

    /// Complete passkey authentication
    ///
    /// # Arguments
    /// * `credential_response` - The credential response from the client
    /// * `authentication_state` - The authentication state from the server
    /// * `user_data` - Optional user data if available
    ///
    /// # Returns
    /// * `Ok(AuthenticationResponse::Session)` - Successful authentication with session data
    /// * `Err(AuthenticationError)` - Authentication failure
    ///
    /// # Errors
    /// Returns an error if:
    /// - The service is not available (passkeys disabled)
    /// - Authentication data is invalid
    /// - `WebAuthn` authentication fails
    /// - Session creation fails
    fn complete_authentication(
        &self,
        credential_response: &webauthn_rs::prelude::PublicKeyCredential,
        authentication_state: &webauthn_rs::prelude::PasskeyAuthentication,
        user_data: Option<&crate::passkey::PasskeyUserData>,
    ) -> Result<crate::models::auth::AuthenticationResult, crate::passkey::PasskeyError>;

    /// Start registration process
    ///
    /// # Arguments
    /// * `email` - User's email address
    /// * `name` - User's display name
    ///
    /// # Returns
    /// * `Ok(AuthenticationResponse::PasskeyRegistrationStart)` - Registration challenge
    /// * `Err(AuthenticationError)` - Registration start failure
    ///
    /// # Errors
    /// Returns an error if:
    /// - The service is not available (passkeys disabled)
    /// - User data is invalid
    /// - `WebAuthn` challenge generation fails
    fn start_registration(
        &self,
        email: &str,
        name: &str,
    ) -> Result<crate::passkey::PasskeyRegistrationStart, crate::passkey::PasskeyError>;

    /// Start authentication process
    ///
    /// # Returns
    /// * `Ok(AuthenticationResponse::PasskeyAuthenticationStart)` - Authentication challenge
    /// * `Err(AuthenticationError)` - Authentication start failure
    ///
    /// # Errors
    /// Returns an error if:
    /// - The service is not available (passkeys disabled)
    /// - `WebAuthn` challenge generation fails
    fn start_authentication(
        &self,
    ) -> Result<crate::passkey::PasskeyAuthenticationStart, crate::passkey::PasskeyError>;
}

/// Session management service trait
///
/// This trait provides session management operations that are used by
/// all authentication services for creating, validating, and managing
/// user sessions.
pub trait SessionService {
    /// Create session cookies from authentication result
    ///
    /// # Arguments
    /// * `result` - The authentication result containing session and user data
    ///
    /// # Returns
    /// * `Ok((session_cookie, user_cookie))` - Encrypted session cookies
    /// * `Err(AuthenticationError)` - Cookie creation failure
    ///
    /// # Errors
    /// Returns an error if:
    /// - Session data encryption fails
    /// - User data encryption fails
    /// - Cookie creation fails
    fn create_session_cookies(
        &self,
        result: &crate::models::auth::AuthenticationResult,
    ) -> Result<
        (
            actix_web::cookie::Cookie<'static>,
            actix_web::cookie::Cookie<'static>,
        ),
        crate::models::auth::AuthenticationError,
    >;

    /// Validate session security (expiration and context)
    ///
    /// # Arguments
    /// * `session` - The session to validate
    /// * `user_data` - The user data for context validation
    /// * `req` - The HTTP request for context extraction
    ///
    /// # Returns
    /// * `Ok(true)` - Session is valid and not expired
    /// * `Ok(false)` - Session is valid but expired (may be refreshable)
    /// * `Err(AuthenticationError)` - Session validation failed
    ///
    /// # Errors
    /// Returns an error if:
    /// - Client context validation fails (session hijacking)
    /// - Session data is corrupted
    fn validate_session_security(
        &self,
        session: &crate::models::VouchrsSession,
        user_data: &crate::models::VouchrsUserData,
        req: &actix_web::HttpRequest,
    ) -> Result<bool, crate::models::auth::AuthenticationError>;
}
